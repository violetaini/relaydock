#!/usr/bin/env python3
"""Run local end-to-end connectivity checks for Arcway managed protocols.

The runner never writes to an Arcway server. It starts two temporary Xray
processes per case on loopback, sends an HTTP request through the client Xray,
and requires the origin probe to observe the server-side exit address.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import dataclasses
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import select
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid


EXPECTED_XRAY_VERSION = "26.3.27"
LOOPBACK = "127.0.0.1"
EXPECTED_EXIT_IP = "127.0.0.2"
WIREGUARD_TEST_TARGET = "198.18.0.1"
TLS_SERVER_NAME = "acceptance.test"
GRPC_SERVICE_NAME = "arcway-acceptance"
WS_PATH = "/arcway-acceptance"


class AcceptanceError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class CaseSpec:
    case_id: str
    managed_preset: str
    family: str
    transport: str = "tcp"
    security: str = "none"
    vision: bool = False
    detail: str = ""


XRAY_CASES = (
    CaseSpec("vless-reality", "vless-reality", "vless", security="reality", vision=True),
    CaseSpec("vless-tls", "vless-tls", "vless", security="tls", vision=True),
    CaseSpec("vless-grpc-tls", "vless-grpc-tls", "vless", transport="grpc", security="tls"),
    CaseSpec("vless-ws", "vless-ws", "vless", transport="ws"),
    CaseSpec("vless-wss", "vless-wss", "vless", transport="ws", security="wss", detail="TLS terminator emulates Nginx"),
    CaseSpec("vmess", "vmess", "vmess"),
    CaseSpec("vmess-tls", "vmess-tls", "vmess", security="tls"),
    CaseSpec("vmess-grpc-tls", "vmess-grpc-tls", "vmess", transport="grpc", security="tls"),
    CaseSpec("vmess-ws", "vmess-ws", "vmess", transport="ws"),
    CaseSpec("vmess-wss", "vmess-wss", "vmess", transport="ws", security="wss", detail="TLS terminator emulates Nginx"),
    CaseSpec("trojan", "trojan", "trojan", security="tls"),
    CaseSpec("trojan-reality", "trojan-reality", "trojan", security="reality"),
    CaseSpec("trojan-grpc-tls", "trojan-grpc-tls", "trojan", transport="grpc", security="tls"),
    CaseSpec("trojan-wss", "trojan-wss", "trojan", transport="ws", security="wss", detail="TLS terminator emulates Nginx"),
    CaseSpec("shadowsocks-classic", "shadowsocks", "shadowsocks-classic", detail="AES-128-GCM"),
    CaseSpec("shadowsocks-2022", "shadowsocks", "shadowsocks-2022", detail="2022 BLAKE3 AES-128-GCM multi-user"),
    CaseSpec("hysteria2", "hysteria2", "hysteria2", transport="hysteria", security="tls", detail="QUIC/UDP transport"),
    CaseSpec("socks5", "socks5", "socks5"),
    CaseSpec("http", "http", "http"),
)

SPECIAL_CASE_IDS = ("wireguard", "anydoor")

MANAGED_PRESET_COVERAGE = {
    "vless-reality": "xray",
    "vless-tls": "xray",
    "vless-grpc-tls": "xray",
    "vless-ws": "xray",
    "vless-wss": "xray+tls-terminator",
    "vmess": "xray",
    "vmess-tls": "xray",
    "vmess-grpc-tls": "xray",
    "vmess-ws": "xray",
    "vmess-wss": "xray+tls-terminator",
    "trojan": "xray",
    "trojan-reality": "xray",
    "trojan-grpc-tls": "xray",
    "trojan-wss": "xray+tls-terminator",
    "shadowsocks": "xray-classic-and-2022",
    "hysteria2": "xray-quic-udp",
    "socks5": "xray",
    "http": "xray",
    "wireguard": "xray-userspace-wireguard",
    "anydoor": "xray-three-hop-tcp-and-udp-chain",
}

SEPARATE_CHECKS = {
    "mihomo-only": "Mihomo config test plus HTTP exit and protocol-promised UDP check",
}


@dataclasses.dataclass
class Credentials:
    client_uuid: str
    password: str
    username: str
    ss_classic_password: str
    ss2022_master: str
    ss2022_user: str
    reality_private: str
    reality_public: str
    reality_short_id: str
    wireguard_server_private: str
    wireguard_server_public: str
    wireguard_client_private: str
    wireguard_client_public: str

    @classmethod
    def create(
        cls,
        reality_private: str,
        reality_public: str,
        wireguard_server: tuple[str, str],
        wireguard_client: tuple[str, str],
    ) -> "Credentials":
        key = lambda: base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        return cls(
            client_uuid=str(uuid.uuid4()),
            password=secrets.token_urlsafe(24),
            username="arcway-acceptance",
            ss_classic_password=secrets.token_urlsafe(24),
            ss2022_master=key(),
            ss2022_user=key(),
            reality_private=reality_private,
            reality_public=reality_public,
            reality_short_id=secrets.token_hex(8),
            wireguard_server_private=wireguard_server[0],
            wireguard_server_public=wireguard_server[1],
            wireguard_client_private=wireguard_client[0],
            wireguard_client_public=wireguard_client[1],
        )

    def secret_values(self) -> list[str]:
        return [
            self.client_uuid,
            self.password,
            self.ss_classic_password,
            self.ss2022_master,
            self.ss2022_user,
            self.reality_private,
            self.reality_public,
            self.reality_short_id,
            self.wireguard_server_private,
            self.wireguard_server_public,
            self.wireguard_client_private,
            self.wireguard_client_public,
        ]


@dataclasses.dataclass(frozen=True)
class Material:
    cert_path: Path
    key_path: Path
    cert_sha256: str
    credentials: Credentials


@dataclasses.dataclass(frozen=True)
class ConfigPair:
    server: dict[str, object]
    client: dict[str, object]
    requires_tls_forwarder: bool


def reserve_ports(count: int, socket_type: int = socket.SOCK_STREAM) -> list[int]:
    sockets: list[socket.socket] = []
    try:
        for _ in range(count):
            sock = socket.socket(socket.AF_INET, socket_type)
            sock.bind((LOOPBACK, 0))
            sockets.append(sock)
        return [int(sock.getsockname()[1]) for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


def reserve_shared_tcp_udp_port(hosts: list[str]) -> int:
    for _ in range(50):
        port_seed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            port_seed.bind((hosts[0], 0))
            port = int(port_seed.getsockname()[1])
        finally:
            port_seed.close()

        sockets: list[socket.socket] = []
        try:
            for host in hosts:
                for socket_type in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                    sock = socket.socket(socket.AF_INET, socket_type)
                    sock.bind((host, port))
                    sockets.append(sock)
            return port
        except OSError:
            continue
        finally:
            for sock in sockets:
                sock.close()
    raise AcceptanceError("Unable to reserve one TCP/UDP port across the loopback tunnel hops")


def secure_write_json(path: Path, value: object) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(value, output, ensure_ascii=True, separators=(",", ":"))
        output.write("\n")


def redact(text: str, secret_values: list[str]) -> str:
    result = text
    for value in sorted((item for item in secret_values if len(item) >= 8), key=len, reverse=True):
        result = result.replace(value, "[REDACTED]")
    result = re.sub(
        r"(?i)(privatekey|publickey|password|shortids?|uuid)(\s*[:=]\s*)[^\s,}\]]+",
        r"\1\2[REDACTED]",
        result,
    )
    result = re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", "[REDACTED]", result, flags=re.I)
    result = re.sub(r"\b[A-Za-z0-9+/_-]{32,}={0,2}\b", "[REDACTED]", result)
    return result[-2000:]


def generate_certificate(directory: Path, openssl_bin: str) -> tuple[Path, Path, str]:
    cert_path = directory / "acceptance-cert.pem"
    key_path = directory / "acceptance-key.pem"
    command = [
        openssl_bin,
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-sha256",
        "-nodes",
        "-days",
        "1",
        "-subj",
        f"/CN={TLS_SERVER_NAME}",
        "-addext",
        f"subjectAltName=DNS:{TLS_SERVER_NAME}",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
    ]
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, timeout=20, check=False)
    if result.returncode != 0:
        raise AcceptanceError(f"OpenSSL certificate generation failed: {redact(result.stderr, [])}")
    key_path.chmod(0o600)
    cert_path.chmod(0o600)
    der = ssl.PEM_cert_to_DER_cert(cert_path.read_text(encoding="ascii"))
    fingerprint = hashlib.sha256(der).hexdigest()
    return cert_path, key_path, fingerprint


def generate_x25519_keys(xray_bin: str, standard_encoding: bool = False) -> tuple[str, str]:
    command = [xray_bin, "x25519"]
    if standard_encoding:
        command.append("--std-encoding")
    result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
    combined = f"{result.stdout}\n{result.stderr}"
    alphabet = r"[A-Za-z0-9+/]{43}=" if standard_encoding else r"[A-Za-z0-9_-]{43}"
    private_match = re.search(rf"(?im)^PrivateKey:\s*({alphabet})\s*$", combined)
    public_match = re.search(rf"(?im)^(?:Password \(PublicKey\)|PublicKey):\s*({alphabet})\s*$", combined)
    if result.returncode != 0 or not private_match or not public_match:
        raise AcceptanceError("Xray did not return a valid in-memory X25519 key pair")
    return private_match.group(1), public_match.group(1)


def server_tls(material: Material, alpn: list[str]) -> dict[str, object]:
    return {
        "serverName": TLS_SERVER_NAME,
        "minVersion": "1.2",
        "alpn": alpn,
        "certificates": [{"certificateFile": str(material.cert_path), "keyFile": str(material.key_path)}],
    }


def client_tls(material: Material, alpn: list[str]) -> dict[str, object]:
    return {
        "serverName": TLS_SERVER_NAME,
        "minVersion": "1.2",
        "alpn": alpn,
        "pinnedPeerCertSha256": material.cert_sha256,
        "verifyPeerCertByName": TLS_SERVER_NAME,
    }


def protocol_settings(spec: CaseSpec, credentials: Credentials, server_port: int) -> tuple[str, dict[str, object], dict[str, object]]:
    if spec.family == "vless":
        server_user: dict[str, object] = {"id": credentials.client_uuid, "email": "admin"}
        client_user: dict[str, object] = {"id": credentials.client_uuid, "encryption": "none"}
        if spec.vision:
            server_user["flow"] = "xtls-rprx-vision"
            client_user["flow"] = "xtls-rprx-vision"
        return (
            "vless",
            {"clients": [server_user], "decryption": "none"},
            {"vnext": [{"address": LOOPBACK, "port": server_port, "users": [client_user]}]},
        )
    if spec.family == "vmess":
        return (
            "vmess",
            {"clients": [{"id": credentials.client_uuid, "email": "admin", "security": "auto", "level": 0}]},
            {"vnext": [{"address": LOOPBACK, "port": server_port, "users": [{"id": credentials.client_uuid, "security": "auto"}]}]},
        )
    if spec.family == "trojan":
        return (
            "trojan",
            {"clients": [{"password": credentials.password, "email": "admin", "level": 0}]},
            {"servers": [{"address": LOOPBACK, "port": server_port, "password": credentials.password}]},
        )
    if spec.family == "shadowsocks-classic":
        return (
            "shadowsocks",
            {"method": "aes-128-gcm", "password": credentials.ss_classic_password, "email": "admin", "network": "tcp,udp"},
            {"servers": [{"address": LOOPBACK, "port": server_port, "method": "aes-128-gcm", "password": credentials.ss_classic_password}]},
        )
    if spec.family == "shadowsocks-2022":
        return (
            "shadowsocks",
            {
                "method": "2022-blake3-aes-128-gcm",
                "password": credentials.ss2022_master,
                "network": "tcp,udp",
                "clients": [{"password": credentials.ss2022_user, "email": "admin", "level": 0}],
            },
            {
                "servers": [{
                    "address": LOOPBACK,
                    "port": server_port,
                    "method": "2022-blake3-aes-128-gcm",
                    "password": f"{credentials.ss2022_master}:{credentials.ss2022_user}",
                }],
            },
        )
    if spec.family == "hysteria2":
        return (
            "hysteria",
            {"version": 2, "clients": [{"auth": credentials.password, "email": "admin", "level": 0}]},
            {"version": 2, "address": LOOPBACK, "port": server_port},
        )
    if spec.family == "socks5":
        account = {"user": credentials.username, "pass": credentials.password}
        return (
            "socks",
            {"auth": "password", "accounts": [account], "udp": True},
            {"servers": [{"address": LOOPBACK, "port": server_port, "users": [account]}]},
        )
    if spec.family == "http":
        account = {"user": credentials.username, "pass": credentials.password}
        return (
            "http",
            {"accounts": [account], "allowTransparent": False},
            {"servers": [{"address": LOOPBACK, "port": server_port, "users": [account]}]},
        )
    raise AcceptanceError(f"Unsupported Xray family: {spec.family}")


def stream_settings(
    spec: CaseSpec,
    material: Material,
    reality_target_port: int,
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    if spec.family in {"shadowsocks-classic", "shadowsocks-2022", "socks5", "http"}:
        return None, None

    network = spec.transport
    if network == "hysteria":
        server = {
            "network": "hysteria",
            "security": "tls",
            "hysteriaSettings": {"version": 2},
            "tlsSettings": server_tls(material, ["h3"]),
        }
        client = {
            "network": "hysteria",
            "security": "tls",
            "hysteriaSettings": {"version": 2, "auth": material.credentials.password},
            "tlsSettings": client_tls(material, ["h3"]),
        }
        return server, client

    common: dict[str, object] = {"network": network}
    if network == "ws":
        common["wsSettings"] = {"path": WS_PATH, "host": TLS_SERVER_NAME}
    elif network == "grpc":
        common["grpcSettings"] = {"serviceName": GRPC_SERVICE_NAME, "multiMode": False}

    if spec.security == "reality":
        server = {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "show": False,
                "target": f"{LOOPBACK}:{reality_target_port}",
                "xver": 0,
                "serverNames": [TLS_SERVER_NAME],
                "privateKey": material.credentials.reality_private,
                "shortIds": [material.credentials.reality_short_id],
            },
        }
        client = {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "fingerprint": "chrome",
                "serverName": TLS_SERVER_NAME,
                "password": material.credentials.reality_public,
                "shortId": material.credentials.reality_short_id,
                "spiderX": "/",
            },
        }
        return server, client

    if spec.security == "wss":
        server = {**common, "security": "none"}
        client = {
            **common,
            "security": "tls",
            "tlsSettings": client_tls(material, ["http/1.1"]),
        }
        return server, client

    if spec.security == "tls":
        alpn = ["h2"] if network == "grpc" else ["h2", "http/1.1"]
        server = {**common, "security": "tls", "tlsSettings": server_tls(material, alpn)}
        client = {**common, "security": "tls", "tlsSettings": client_tls(material, alpn)}
        return server, client

    return {**common, "security": "none"}, {**common, "security": "none"}


def build_config_pair(
    spec: CaseSpec,
    material: Material,
    server_port: int,
    edge_port: int,
    client_socks_port: int,
    reality_target_port: int,
) -> ConfigPair:
    protocol, inbound_settings, outbound_settings = protocol_settings(spec, material.credentials, edge_port)
    server_stream, client_stream = stream_settings(spec, material, reality_target_port)
    inbound: dict[str, object] = {
        "tag": f"acceptance-{spec.case_id}",
        "listen": LOOPBACK,
        "port": server_port,
        "protocol": protocol,
        "settings": inbound_settings,
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False},
    }
    if server_stream is not None:
        inbound["streamSettings"] = server_stream
    outbound: dict[str, object] = {
        "tag": "tested-protocol",
        "protocol": protocol,
        "settings": outbound_settings,
    }
    if client_stream is not None:
        outbound["streamSettings"] = client_stream
    server = {
        "log": {"loglevel": "none"},
        "inbounds": [inbound],
        "outbounds": [{
            "tag": "acceptance-exit",
            "protocol": "freedom",
            "sendThrough": EXPECTED_EXIT_IP,
            "settings": {"domainStrategy": "UseIP"},
        }],
    }
    client = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "tag": "acceptance-socks",
            "listen": LOOPBACK,
            "port": client_socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [outbound],
    }
    return ConfigPair(server=server, client=client, requires_tls_forwarder=spec.security == "wss")


def build_wireguard_pair(
    material: Material,
    server_port: int,
    client_socks_port: int,
    origin_port: int,
) -> ConfigPair:
    credentials = material.credentials
    server = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "tag": "acceptance-wireguard",
            "listen": LOOPBACK,
            "port": server_port,
            "protocol": "wireguard",
            "settings": {
                "secretKey": credentials.wireguard_server_private,
                "address": ["10.66.66.1/32"],
                "mtu": 1420,
                "noKernelTun": False,
                "peers": [{
                    "publicKey": credentials.wireguard_client_public,
                    "allowedIPs": ["10.66.66.2/32"],
                    "keepAlive": 25,
                }],
            },
            "sniffing": {"enabled": False},
        }],
        "outbounds": [{
            "tag": "acceptance-exit",
            "protocol": "freedom",
            "sendThrough": EXPECTED_EXIT_IP,
            "settings": {
                "domainStrategy": "UseIP",
                "redirect": f"{LOOPBACK}:{origin_port}",
            },
        }],
    }
    client = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "tag": "acceptance-socks",
            "listen": LOOPBACK,
            "port": client_socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [{
            "tag": "tested-wireguard",
            "protocol": "wireguard",
            "settings": {
                "secretKey": credentials.wireguard_client_private,
                "address": ["10.66.66.2/32"],
                "mtu": 1420,
                "noKernelTun": True,
                "domainStrategy": "ForceIPv4",
                "peers": [{
                    "publicKey": credentials.wireguard_server_public,
                    "endpoint": f"{LOOPBACK}:{server_port}",
                    "allowedIPs": ["0.0.0.0/0"],
                    "keepAlive": 25,
                }],
            },
        }],
    }
    return ConfigPair(server=server, client=client, requires_tls_forwarder=False)


def build_anydoor_config(
    tag: str,
    listen_host: str,
    listen_port: int,
    target_host: str,
    target_port: int,
    send_through: str | None = None,
) -> dict[str, object]:
    outbound: dict[str, object] = {
        "tag": f"{tag}-exit",
        "protocol": "freedom",
        "settings": {"domainStrategy": "UseIP"},
    }
    if send_through is not None:
        outbound["sendThrough"] = send_through
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "tag": tag,
            "listen": listen_host,
            "port": listen_port,
            "protocol": "tunnel",
            "settings": {
                "address": target_host,
                "port": target_port,
                "network": "tcp,udp",
                "followRedirect": False,
            },
            "sniffing": {"enabled": False},
        }],
        "outbounds": [outbound],
    }


class ProbeServer:
    def __init__(self) -> None:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(handler_self) -> None:  # noqa: N802
                token = handler_self.path.removeprefix("/probe/").split("?", 1)[0]
                body = json.dumps({"token": token, "remote_ip": handler_self.client_address[0]}).encode("utf-8")
                handler_self.send_response(200)
                handler_self.send_header("Content-Type", "application/json")
                handler_self.send_header("Content-Length", str(len(body)))
                handler_self.end_headers()
                handler_self.wfile.write(body)

            def log_message(self, _format: str, *_args: object) -> None:
                return

        self.server = http.server.ThreadingHTTPServer((LOOPBACK, 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, name="arcway-probe", daemon=True)
        self.stop_event = threading.Event()
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_socket.bind((LOOPBACK, self.port))
        self.udp_socket.settimeout(0.2)
        self.udp_thread = threading.Thread(target=self._serve_udp, name="arcway-udp-probe", daemon=True)

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def start(self) -> None:
        self.thread.start()
        self.udp_thread.start()

    def _serve_udp(self) -> None:
        while not self.stop_event.is_set():
            try:
                payload, address = self.udp_socket.recvfrom(65535)
                response = json.dumps({
                    "token": payload.decode("ascii"),
                    "remote_ip": address[0],
                }).encode("ascii")
                self.udp_socket.sendto(response, address)
            except TimeoutError:
                continue
            except (OSError, UnicodeDecodeError):
                if self.stop_event.is_set():
                    return

    def close(self) -> None:
        self.stop_event.set()
        self.udp_socket.close()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.udp_thread.join(timeout=2)


class CamouflageServer:
    def __init__(self, material: Material) -> None:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(handler_self) -> None:  # noqa: N802
                body = b"ok\n"
                handler_self.send_response(200)
                handler_self.send_header("Content-Length", str(len(body)))
                handler_self.end_headers()
                handler_self.wfile.write(body)

            def log_message(self, _format: str, *_args: object) -> None:
                return

        self.server = http.server.ThreadingHTTPServer((LOOPBACK, 0), Handler)
        self.server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(material.cert_path), str(material.key_path))
        context.set_alpn_protocols(["h2", "http/1.1"])
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, name="arcway-camouflage", daemon=True)

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class TLSForwarder:
    def __init__(self, listen_port: int, upstream_port: int, material: Material) -> None:
        self.stop_event = threading.Event()
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_socket.bind((LOOPBACK, listen_port))
        self.listen_socket.listen(16)
        self.listen_socket.settimeout(0.2)
        self.upstream_port = upstream_port
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(str(material.cert_path), str(material.key_path))
        self.context.set_alpn_protocols(["http/1.1"])
        self.thread = threading.Thread(target=self._accept, name="arcway-tls-forwarder", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _accept(self) -> None:
        while not self.stop_event.is_set():
            try:
                raw, _ = self.listen_socket.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(raw,), daemon=True).start()

    def _handle(self, raw: socket.socket) -> None:
        raw.settimeout(5)
        try:
            downstream = self.context.wrap_socket(raw, server_side=True)
            upstream = socket.create_connection((LOOPBACK, self.upstream_port), timeout=5)
        except (OSError, ssl.SSLError):
            raw.close()
            return
        downstream.settimeout(None)
        upstream.settimeout(None)
        with contextlib.closing(downstream), contextlib.closing(upstream):
            sockets = [downstream, upstream]
            while not self.stop_event.is_set():
                try:
                    readable, _, _ = select.select(sockets, [], [], 0.2)
                    for source in readable:
                        data = source.recv(65536)
                        if not data:
                            return
                        destination = upstream if source is downstream else downstream
                        destination.sendall(data)
                except (OSError, ssl.SSLError):
                    return

    def close(self) -> None:
        self.stop_event.set()
        self.listen_socket.close()
        self.thread.join(timeout=2)


class XrayProcess:
    def __init__(self, xray_bin: str, config_path: Path) -> None:
        self.process = subprocess.Popen(
            [xray_bin, "run", "-config", str(config_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

    def close(self) -> None:
        if self.process.poll() is not None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=3)


def wait_for_listener(host: str, port: int, process: XrayProcess, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.process.poll() is not None:
            raise AcceptanceError("Xray exited before its listener became ready")
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AcceptanceError(f"Timed out waiting for loopback listener on {host}:{port}")


def wait_for_process_alive(process: XrayProcess, timeout: float) -> None:
    deadline = time.monotonic() + min(timeout, 0.4)
    while time.monotonic() < deadline:
        if process.process.poll() is not None:
            raise AcceptanceError("Xray exited during listener startup")
        time.sleep(0.05)


def validate_xray_config(xray_bin: str, config_path: Path, secrets_to_hide: list[str], timeout: float) -> None:
    try:
        result = subprocess.run(
            [xray_bin, "run", "-test", "-config", str(config_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as reason:
        raise AcceptanceError("Xray config validation timed out") from reason
    if result.returncode != 0:
        detail = redact(f"{result.stdout}\n{result.stderr}", secrets_to_hide)
        raise AcceptanceError(f"Xray rejected generated config: {detail}")


def verify_probe_payload(raw_payload: str, token: str) -> None:
    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError as reason:
        raise AcceptanceError("Origin returned a non-JSON response") from reason
    if payload.get("token") != token:
        raise AcceptanceError("Origin response token did not match the request")
    if payload.get("remote_ip") != EXPECTED_EXIT_IP:
        raise AcceptanceError(f"Origin observed {payload.get('remote_ip')!r}, expected server exit {EXPECTED_EXIT_IP}")


def run_http_probe(
    curl_bin: str,
    socks_port: int,
    origin_port: int,
    timeout: float,
    target_host: str = LOOPBACK,
    target_port: int | None = None,
) -> None:
    token = secrets.token_hex(16)
    result = subprocess.run(
        [
            curl_bin,
            "--silent",
            "--show-error",
            "--fail-with-body",
            "--max-time",
            str(timeout),
            "--noproxy",
            "",
            "--proxy",
            f"socks5h://{LOOPBACK}:{socks_port}",
            f"http://{target_host}:{target_port or origin_port}/probe/{token}",
        ],
        capture_output=True,
        text=True,
        timeout=timeout + 2,
        check=False,
    )
    if result.returncode != 0:
        raise AcceptanceError(f"HTTP request through client Xray failed: {redact(result.stderr, [token])}")
    verify_probe_payload(result.stdout, token)


def run_direct_http_probe(curl_bin: str, host: str, port: int, timeout: float) -> None:
    token = secrets.token_hex(16)
    result = subprocess.run(
        [
            curl_bin,
            "--silent",
            "--show-error",
            "--fail-with-body",
            "--max-time",
            str(timeout),
            "--noproxy",
            "*",
            f"http://{host}:{port}/probe/{token}",
        ],
        capture_output=True,
        text=True,
        timeout=timeout + 2,
        check=False,
    )
    if result.returncode != 0:
        raise AcceptanceError(f"HTTP request through the tunnel chain failed: {redact(result.stderr, [token])}")
    verify_probe_payload(result.stdout, token)


def run_udp_probe(host: str, port: int, timeout: float) -> None:
    token = secrets.token_hex(16)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.sendto(token.encode("ascii"), (host, port))
        try:
            response, _ = client.recvfrom(65535)
        except TimeoutError as reason:
            raise AcceptanceError("UDP request through the tunnel chain timed out") from reason
    verify_probe_payload(response.decode("ascii"), token)


def check_xray_version(xray_bin: str, expected: str) -> None:
    result = subprocess.run([xray_bin, "version"], capture_output=True, text=True, timeout=10, check=False)
    match = re.search(r"(?m)^Xray\s+(\d+\.\d+\.\d+)\b", result.stdout)
    if result.returncode != 0 or not match:
        raise AcceptanceError("Unable to read Xray version")
    if match.group(1) != expected:
        raise AcceptanceError(f"Xray version {match.group(1)} does not match required {expected}")


def resolve_executable(explicit: str | None, environment_name: str, fallback: str) -> str:
    candidate = explicit or os.environ.get(environment_name) or shutil.which(fallback)
    if not candidate:
        raise AcceptanceError(f"Required executable not found: set {environment_name} or use the matching CLI option")
    resolved = str(Path(candidate).expanduser().resolve())
    if not os.path.isfile(resolved) or not os.access(resolved, os.X_OK):
        raise AcceptanceError(f"Executable is not runnable: {resolved}")
    return resolved


def run_case(
    spec: CaseSpec,
    material: Material,
    work_dir: Path,
    xray_bin: str,
    curl_bin: str | None,
    origin_port: int,
    reality_target_port: int,
    timeout: float,
    validate_only: bool,
) -> None:
    if spec.family == "hysteria2":
        server_port = reserve_ports(1, socket.SOCK_DGRAM)[0]
        edge_port = server_port
        socks_port = reserve_ports(1)[0]
    else:
        server_port, edge_port, socks_port = reserve_ports(3)
        if spec.security != "wss":
            edge_port = server_port
    pair = build_config_pair(spec, material, server_port, edge_port, socks_port, reality_target_port)
    server_path = work_dir / f"{spec.case_id}-server.json"
    client_path = work_dir / f"{spec.case_id}-client.json"
    secure_write_json(server_path, pair.server)
    secure_write_json(client_path, pair.client)
    secret_values = material.credentials.secret_values()
    validate_xray_config(xray_bin, server_path, secret_values, timeout)
    validate_xray_config(xray_bin, client_path, secret_values, timeout)
    if validate_only:
        return
    if curl_bin is None:
        raise AcceptanceError("curl is required for connectivity mode")

    server_process: XrayProcess | None = None
    client_process: XrayProcess | None = None
    forwarder: TLSForwarder | None = None
    try:
        server_process = XrayProcess(xray_bin, server_path)
        if spec.family == "hysteria2":
            wait_for_process_alive(server_process, timeout)
        else:
            wait_for_listener(LOOPBACK, server_port, server_process, timeout)
        if pair.requires_tls_forwarder:
            forwarder = TLSForwarder(edge_port, server_port, material)
            forwarder.start()
        client_process = XrayProcess(xray_bin, client_path)
        wait_for_listener(LOOPBACK, socks_port, client_process, timeout)
        run_http_probe(curl_bin, socks_port, origin_port, timeout)
    finally:
        if client_process is not None:
            client_process.close()
        if forwarder is not None:
            forwarder.close()
        if server_process is not None:
            server_process.close()


def run_wireguard_case(
    material: Material,
    work_dir: Path,
    xray_bin: str,
    curl_bin: str | None,
    origin_port: int,
    timeout: float,
    validate_only: bool,
) -> None:
    server_port = reserve_ports(1, socket.SOCK_DGRAM)[0]
    socks_port = reserve_ports(1)[0]
    pair = build_wireguard_pair(material, server_port, socks_port, origin_port)
    server_path = work_dir / "wireguard-server.json"
    client_path = work_dir / "wireguard-client.json"
    secure_write_json(server_path, pair.server)
    secure_write_json(client_path, pair.client)
    secret_values = material.credentials.secret_values()
    validate_xray_config(xray_bin, server_path, secret_values, timeout)
    validate_xray_config(xray_bin, client_path, secret_values, timeout)
    if validate_only:
        return
    if curl_bin is None:
        raise AcceptanceError("curl is required for connectivity mode")

    server_process: XrayProcess | None = None
    client_process: XrayProcess | None = None
    try:
        server_process = XrayProcess(xray_bin, server_path)
        wait_for_process_alive(server_process, timeout)
        client_process = XrayProcess(xray_bin, client_path)
        wait_for_listener(LOOPBACK, socks_port, client_process, timeout)
        run_http_probe(
            curl_bin,
            socks_port,
            origin_port,
            timeout,
            target_host=WIREGUARD_TEST_TARGET,
            target_port=80,
        )
    finally:
        if client_process is not None:
            client_process.close()
        if server_process is not None:
            server_process.close()


def run_anydoor_case(
    work_dir: Path,
    xray_bin: str,
    curl_bin: str | None,
    origin_port: int,
    timeout: float,
    validate_only: bool,
) -> None:
    hop_hosts = ["127.0.0.10", "127.0.0.11", "127.0.0.12"]
    tunnel_port = reserve_shared_tcp_udp_port(hop_hosts)
    configs = [
        build_anydoor_config("acceptance-anydoor-a", hop_hosts[0], tunnel_port, hop_hosts[1], tunnel_port),
        build_anydoor_config("acceptance-anydoor-b", hop_hosts[1], tunnel_port, hop_hosts[2], tunnel_port),
        build_anydoor_config(
            "acceptance-anydoor-c",
            hop_hosts[2],
            tunnel_port,
            LOOPBACK,
            origin_port,
            send_through=EXPECTED_EXIT_IP,
        ),
    ]
    paths: list[Path] = []
    for name, config in zip(("a", "b", "c"), configs, strict=True):
        path = work_dir / f"anydoor-{name}.json"
        secure_write_json(path, config)
        validate_xray_config(xray_bin, path, [], timeout)
        paths.append(path)
    if validate_only:
        return
    if curl_bin is None:
        raise AcceptanceError("curl is required for connectivity mode")

    processes: list[XrayProcess] = []
    try:
        for index in (2, 1, 0):
            process = XrayProcess(xray_bin, paths[index])
            processes.append(process)
            wait_for_listener(hop_hosts[index], tunnel_port, process, timeout)
        run_direct_http_probe(curl_bin, hop_hosts[0], tunnel_port, timeout)
        run_udp_probe(hop_hosts[0], tunnel_port, timeout)
    finally:
        for process in reversed(processes):
            process.close()


def print_matrix() -> None:
    print(f"Managed protocol coverage: {len(MANAGED_PRESET_COVERAGE)} UI presets, {len(XRAY_CASES) + len(SPECIAL_CASE_IDS)} executable cases")
    print("Xray protocol cases:")
    for spec in XRAY_CASES:
        suffix = f" ({spec.detail})" if spec.detail else ""
        print(f"  {spec.case_id}: managed preset {spec.managed_preset}{suffix}")
    print("Special managed cases:")
    print("  wireguard: userspace Xray client to Xray WireGuard inbound, then HTTP exit")
    print("  anydoor: three loopback hops on one shared port, then TCP HTTP and UDP nonce checks")
    print("Imported or external-engine checks:")
    for name, description in SEPARATE_CHECKS.items():
        print(f"  {name}: {description}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="list the coverage matrix without starting processes")
    parser.add_argument(
        "--case",
        action="append",
        choices=[item.case_id for item in XRAY_CASES] + list(SPECIAL_CASE_IDS),
        help="run only this case; repeat as needed",
    )
    parser.add_argument("--xray-bin", help="path to the Xray CLI; defaults to ARCWAY_ACCEPTANCE_XRAY_BIN or PATH")
    parser.add_argument("--curl-bin", help="path to curl; defaults to ARCWAY_ACCEPTANCE_CURL_BIN or PATH")
    parser.add_argument("--openssl-bin", help="path to openssl; defaults to ARCWAY_ACCEPTANCE_OPENSSL_BIN or PATH")
    parser.add_argument("--expected-xray-version", default=EXPECTED_XRAY_VERSION, help="exact Xray version required before any case runs")
    parser.add_argument("--validate-only", action="store_true", help="run Xray config validation without opening protocol connections")
    parser.add_argument("--fail-fast", action="store_true", help="stop after the first failed case")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-operation timeout in seconds")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    if args.list:
        print_matrix()
        return 0
    if args.timeout < 1 or args.timeout > 120:
        print("ERROR: --timeout must be between 1 and 120 seconds", file=sys.stderr)
        return 2

    try:
        xray_bin = resolve_executable(args.xray_bin, "ARCWAY_ACCEPTANCE_XRAY_BIN", "xray")
        openssl_bin = resolve_executable(args.openssl_bin, "ARCWAY_ACCEPTANCE_OPENSSL_BIN", "openssl")
        curl_bin = None if args.validate_only else resolve_executable(args.curl_bin, "ARCWAY_ACCEPTANCE_CURL_BIN", "curl")
        check_xray_version(xray_bin, args.expected_xray_version)
    except AcceptanceError as reason:
        print(f"ERROR: {redact(str(reason), [])}", file=sys.stderr)
        return 2

    selected_ids = [item.case_id for item in XRAY_CASES] + list(SPECIAL_CASE_IDS)
    if args.case:
        selected_ids = [case_id for case_id in selected_ids if case_id in args.case]
    specs_by_id = {item.case_id: item for item in XRAY_CASES}
    old_umask = os.umask(0o077)
    failures = 0
    try:
        with tempfile.TemporaryDirectory(prefix="arcway-protocol-acceptance-") as temporary:
            work_dir = Path(temporary)
            work_dir.chmod(0o700)
            cert_path, key_path, cert_sha256 = generate_certificate(work_dir, openssl_bin)
            reality_private, reality_public = generate_x25519_keys(xray_bin)
            wireguard_server = generate_x25519_keys(xray_bin, standard_encoding=True)
            wireguard_client = generate_x25519_keys(xray_bin, standard_encoding=True)
            credentials = Credentials.create(
                reality_private,
                reality_public,
                wireguard_server,
                wireguard_client,
            )
            material = Material(cert_path, key_path, cert_sha256, credentials)

            probe: ProbeServer | None = None
            camouflage: CamouflageServer | None = None
            try:
                if args.validate_only:
                    origin_port, reality_target_port = reserve_ports(2)
                else:
                    probe = ProbeServer()
                    camouflage = CamouflageServer(material)
                    probe.start()
                    camouflage.start()
                    origin_port = probe.port
                    reality_target_port = camouflage.port

                print(f"Xray {args.expected_xray_version}; {len(selected_ids)} case(s); mode={'validate' if args.validate_only else 'connectivity'}")
                for case_id in selected_ids:
                    try:
                        if case_id == "wireguard":
                            run_wireguard_case(
                                material,
                                work_dir,
                                xray_bin,
                                curl_bin,
                                origin_port,
                                args.timeout,
                                args.validate_only,
                            )
                        elif case_id == "anydoor":
                            run_anydoor_case(
                                work_dir,
                                xray_bin,
                                curl_bin,
                                origin_port,
                                args.timeout,
                                args.validate_only,
                            )
                        else:
                            run_case(
                                specs_by_id[case_id],
                                material,
                                work_dir,
                                xray_bin,
                                curl_bin,
                                origin_port,
                                reality_target_port,
                                args.timeout,
                                args.validate_only,
                            )
                        print(f"PASS {case_id}")
                    except (AcceptanceError, OSError, subprocess.SubprocessError) as reason:
                        failures += 1
                        print(f"FAIL {case_id}: {redact(str(reason), credentials.secret_values())}", file=sys.stderr)
                        if args.fail_fast:
                            break
            finally:
                if camouflage is not None:
                    camouflage.close()
                if probe is not None:
                    probe.close()
    except (AcceptanceError, OSError, subprocess.SubprocessError) as reason:
        print(f"ERROR: {redact(str(reason), [])}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted; temporary processes and credentials were cleaned up", file=sys.stderr)
        return 130
    finally:
        os.umask(old_umask)

    if failures:
        print(f"FAILED: {failures} of {len(selected_ids)} case(s)", file=sys.stderr)
        return 1
    print(f"PASSED: {len(selected_ids)} of {len(selected_ids)} case(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
