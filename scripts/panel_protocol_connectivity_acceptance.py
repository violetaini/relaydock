#!/usr/bin/env python3
"""Create and verify disposable Arcway managed protocol nodes.

Nothing is written unless --execute is present. Authentication is read only
from an environment variable. Cleanup accepts only this run's tag prefix.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

LOCAL_RUNNER_PATH = Path(__file__).with_name("protocol_connectivity_acceptance.py")
LOCAL_SPEC = importlib.util.spec_from_file_location("arcway_local_acceptance", LOCAL_RUNNER_PATH)
if LOCAL_SPEC is None or LOCAL_SPEC.loader is None:
    raise RuntimeError("cannot load protocol_connectivity_acceptance.py")
local_acceptance = importlib.util.module_from_spec(LOCAL_SPEC)
sys.modules[LOCAL_SPEC.name] = local_acceptance
LOCAL_SPEC.loader.exec_module(local_acceptance)

EXPECTED_XRAY_VERSION = local_acceptance.EXPECTED_XRAY_VERSION
LOOPBACK = local_acceptance.LOOPBACK
DEFAULT_TOKEN_ENV = "ARCWAY_ACCEPTANCE_TOKEN"
DEFAULT_CASES = (
    "vless-reality", "vless-tls", "vless-grpc-tls", "vless-ws", "vless-wss",
    "vmess", "vmess-tls", "vmess-grpc-tls", "vmess-ws", "vmess-wss",
    "trojan", "trojan-reality", "trojan-grpc-tls", "trojan-wss",
    "shadowsocks-classic", "shadowsocks-2022", "hysteria2", "socks5", "http",
)
TLS_CASES = {"vless-tls", "vless-grpc-tls", "vmess-tls", "vmess-grpc-tls", "trojan", "trojan-grpc-tls", "hysteria2"}
WSS_CASES = {"vless-wss", "vmess-wss", "trojan-wss"}
REALITY_CASES = {"vless-reality", "trojan-reality"}
SENSITIVE_KEYS = {
    "password", "pass", "auth", "uuid", "id", "privatekey", "publickey",
    "secretkey", "short-id", "shortid",
}


class PanelAcceptanceError(RuntimeError):
    pass


class PanelAPI:
    def __init__(self, base_url: str, token: str, timeout: float, ca_file: str | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        context = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))

    def request(self, method: str, path: str, body: object | None = None) -> object:
        payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        headers = {"Accept": "application/json", "MM-Authorization": self.token}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base_url + path, data=payload, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(2 << 20)
        except urllib.error.HTTPError as reason:
            detail = reason.read(8192).decode("utf-8", "replace")
            try:
                parsed = json.loads(detail)
                detail = str(parsed.get("error") or parsed.get("message") or "request rejected")
            except (json.JSONDecodeError, AttributeError):
                detail = re.sub(r"\s+", " ", detail).strip() or "request rejected"
            raise PanelAcceptanceError(f"panel returned HTTP {reason.code}: {detail[:400]}") from reason
        except urllib.error.URLError as reason:
            raise PanelAcceptanceError(f"cannot reach panel: {reason.reason}") from reason
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError as reason:
            raise PanelAcceptanceError("panel returned non-JSON data") from reason


def random_b64(size: int) -> str:
    return base64.b64encode(secrets.token_bytes(size)).decode("ascii")


def safe_run_id(value: str | None = None) -> str:
    if value is None:
        return time.strftime("%Y%m%d%H%M%S", time.gmtime()) + "-" + secrets.token_hex(3)
    normalized = value.strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{5,40}", normalized):
        raise PanelAcceptanceError("run id must be 6-41 lowercase letters, digits, or hyphens")
    return normalized


def tag_prefix(run_id: str) -> str:
    return f"accept-{run_id}-"


def require_owned_tag(tag: str, prefix: str) -> None:
    if not tag.startswith(prefix) or not re.fullmatch(r"[a-z0-9-]+", tag):
        raise PanelAcceptanceError(f"refusing cleanup outside run prefix {prefix!r}")


def common_inbound(tag: str, port: int, protocol: str, settings: dict[str, object]) -> dict[str, object]:
    return {
        "tag": tag, "listen": "0.0.0.0", "port": port, "protocol": protocol, "settings": settings,
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False},
    }


def tls_stream(domain: str, grpc_service: str | None = None) -> dict[str, object]:
    stream: dict[str, object] = {
        "network": "tcp", "security": "tls",
        "tlsSettings": {"serverName": domain, "alpn": ["h2", "http/1.1"]},
    }
    if grpc_service:
        stream.update(network="grpc", grpcSettings={"serviceName": grpc_service, "multiMode": False})
        stream["tlsSettings"] = {"serverName": domain, "alpn": ["h2"]}
    return stream


def reality_stream(domain: str, private_key: str, short_id: str) -> dict[str, object]:
    return {
        "network": "tcp", "security": "reality",
        "realitySettings": {
            "show": False, "target": f"{domain}:443", "xver": 0, "serverNames": [domain],
            "privateKey": private_key, "shortIds": [short_id],
        },
    }


def ws_stream(path: str, host: str, wss: bool) -> tuple[str, dict[str, object]]:
    settings: dict[str, object] = {"path": path}
    if host:
        settings["host"] = host
    return ("127.0.0.1" if wss else "0.0.0.0"), {"network": "ws", "security": "none", "wsSettings": settings}


def build_create_request(case_id: str, prefix: str, port: int, certificate_id: int | None,
                         tls_domain: str, wss_domain: str, reality_domain: str,
                         reality_keys: tuple[str, str] | None,
                         skip_cert_verify: bool = False) -> tuple[str, dict[str, object]]:
    if case_id not in DEFAULT_CASES:
        raise PanelAcceptanceError(f"unsupported case: {case_id}")
    tag = prefix + case_id
    client_uuid = str(uuid.uuid4())
    password = secrets.token_urlsafe(24)
    grpc_service = "acceptance-" + secrets.token_hex(6)
    path = "/acceptance/" + secrets.token_hex(8)
    inbound: dict[str, object]
    if case_id.startswith("vless"):
        client: dict[str, object] = {"id": client_uuid, "email": "admin"}
        if case_id in {"vless-reality", "vless-tls"}:
            client["flow"] = "xtls-rprx-vision"
        inbound = common_inbound(tag, port, "vless", {"clients": [client], "decryption": "none"})
    elif case_id.startswith("vmess"):
        inbound = common_inbound(tag, port, "vmess", {"clients": [{"id": client_uuid, "email": "admin", "security": "auto", "level": 0}]})
    elif case_id.startswith("trojan"):
        inbound = common_inbound(tag, port, "trojan", {"clients": [{"password": password, "email": "admin", "level": 0}]})
    elif case_id.startswith("shadowsocks"):
        if case_id == "shadowsocks-2022":
            settings = {"method": "2022-blake3-aes-128-gcm", "password": random_b64(16), "network": "tcp,udp",
                        "clients": [{"password": random_b64(16), "email": "admin", "level": 0}]}
        else:
            settings = {"method": "aes-128-gcm", "password": password, "email": "admin", "network": "tcp,udp"}
        inbound = common_inbound(tag, port, "shadowsocks", settings)
    elif case_id == "hysteria2":
        inbound = common_inbound(tag, port, "hysteria", {"version": 2, "clients": [{"auth": password, "email": "admin", "level": 0}]})
    elif case_id == "socks5":
        inbound = common_inbound(tag, port, "socks", {"auth": "password", "accounts": [{"user": "acceptance", "pass": password}], "udp": True})
    elif case_id == "http":
        inbound = common_inbound(tag, port, "http", {"accounts": [{"user": "acceptance", "pass": password}], "allowTransparent": False})
    else:
        raise PanelAcceptanceError(f"unsupported case: {case_id}")

    request: dict[str, object] = {"action": "add", "node_name": "Acceptance " + case_id, "ip_version": "v4", "inbound": inbound}
    if case_id in TLS_CASES:
        if not certificate_id or not tls_domain:
            raise PanelAcceptanceError(f"{case_id} requires --certificate-id and --tls-domain")
        inbound["cert_id"] = certificate_id
        if case_id == "hysteria2":
            stream = tls_stream(tls_domain)
            stream.update(network="hysteria", hysteriaSettings={"version": 2})
            stream["tlsSettings"] = {"serverName": tls_domain, "alpn": ["h3"]}
            inbound["streamSettings"] = stream
        else:
            inbound["streamSettings"] = tls_stream(tls_domain, grpc_service if "grpc" in case_id else None)
        if skip_cert_verify:
            request["client_options"] = {"skip_cert_verify": True}
    elif case_id in REALITY_CASES:
        if not reality_domain or reality_keys is None:
            raise PanelAcceptanceError(f"{case_id} requires --reality-domain and generated X25519 keys")
        inbound["streamSettings"] = reality_stream(reality_domain, reality_keys[0], secrets.token_hex(8))
    elif case_id in WSS_CASES:
        if not wss_domain:
            raise PanelAcceptanceError(f"{case_id} requires --wss-domain")
        inbound["listen"], inbound["streamSettings"] = ws_stream(path, wss_domain, True)
    elif case_id in {"vless-ws", "vmess-ws"}:
        _, inbound["streamSettings"] = ws_stream(path, "", False)
    elif case_id == "vmess":
        inbound["streamSettings"] = {"network": "tcp", "security": "none"}
    return tag, request


def collect_secrets(value: object) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in SENSITIVE_KEYS and isinstance(child, str) and len(child) >= 8:
                found.append(child)
            found.extend(collect_secrets(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(collect_secrets(child))
    return found


def clash_to_xray_outbound(proxy: dict[str, object], pinned_cert_sha256: str = "") -> dict[str, object]:
    proxy_type = str(proxy.get("type", ""))
    address, port = str(proxy.get("server", "")), int(proxy.get("port", 0))
    if not address or not 1 <= port <= 65535:
        raise PanelAcceptanceError("persisted node has no usable server/port")
    outbound: dict[str, object] = {"tag": "tested-protocol"}
    if proxy_type == "vless":
        user: dict[str, object] = {"id": proxy.get("uuid"), "encryption": proxy.get("encryption", "none"), "level": 0}
        if proxy.get("flow"):
            user["flow"] = proxy["flow"]
        outbound.update(protocol="vless", settings={"vnext": [{"address": address, "port": port, "users": [user]}]})
    elif proxy_type == "vmess":
        user = {"id": proxy.get("uuid"), "security": proxy.get("cipher", "auto"), "alterId": int(proxy.get("alterId", 0)), "level": 0}
        outbound.update(protocol="vmess", settings={"vnext": [{"address": address, "port": port, "users": [user]}]})
    elif proxy_type == "trojan":
        server: dict[str, object] = {"address": address, "port": port, "password": proxy.get("password"), "level": 0}
        if proxy.get("flow"):
            server["flow"] = proxy["flow"]
        outbound.update(protocol="trojan", settings={"servers": [server]})
    elif proxy_type == "ss":
        outbound.update(protocol="shadowsocks", settings={"servers": [{"address": address, "port": port, "method": proxy.get("cipher"), "password": proxy.get("password")}]})
    elif proxy_type == "hysteria2":
        outbound.update(protocol="hysteria", settings={"version": 2, "address": address, "port": port})
    elif proxy_type in {"socks", "http"}:
        account = {"user": proxy.get("username", ""), "pass": proxy.get("password", "")}
        outbound.update(protocol=proxy_type, settings={"servers": [{"address": address, "port": port, "users": [account]}]})
    else:
        raise PanelAcceptanceError(f"unsupported persisted Clash type: {proxy_type!r}")

    if proxy_type in {"vless", "vmess", "trojan"}:
        network = str(proxy.get("network") or "tcp")
        stream: dict[str, object] = {"network": network, "security": "none"}
        if proxy.get("reality-opts"):
            reality = dict(proxy["reality-opts"])
            stream["security"] = "reality"
            stream["realitySettings"] = {
                "fingerprint": proxy.get("client-fingerprint", "chrome"),
                "serverName": proxy.get("servername") or proxy.get("sni"),
                "password": reality.get("public-key"), "shortId": reality.get("short-id", ""),
                "spiderX": reality.get("spider-x", "/"),
            }
        elif proxy.get("tls"):
            tls: dict[str, object] = {"serverName": proxy.get("servername") or proxy.get("sni") or address}
            if pinned_cert_sha256:
                tls["pinnedPeerCertSha256"] = pinned_cert_sha256
            if proxy.get("alpn"):
                tls["alpn"] = proxy["alpn"]
            stream.update(security="tls", tlsSettings=tls)
        if network == "ws":
            options = dict(proxy.get("ws-opts") or {})
            ws: dict[str, object] = {"path": options.get("path", "/")}
            host = dict(options.get("headers") or {}).get("Host")
            if host:
                ws["host"] = host
            stream["wsSettings"] = ws
        elif network == "grpc":
            options = dict(proxy.get("grpc-opts") or {})
            stream["grpcSettings"] = {"serviceName": options.get("grpc-service-name", ""), "multiMode": False}
        outbound["streamSettings"] = stream
    elif proxy_type == "hysteria2":
        outbound["streamSettings"] = {
            "network": "hysteria", "security": "tls",
            "hysteriaSettings": {"version": 2, "auth": proxy.get("password")},
            "tlsSettings": {
                "serverName": proxy.get("sni") or address,
                **({"pinnedPeerCertSha256": pinned_cert_sha256} if pinned_cert_sha256 else {}),
                "alpn": ["h3"],
            },
        }
    return outbound


def build_client_config(proxy: dict[str, object], socks_port: int, pinned_cert_sha256: str = "") -> dict[str, object]:
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"tag": "acceptance-socks", "listen": LOOPBACK, "port": socks_port,
                      "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
        "outbounds": [clash_to_xray_outbound(proxy, pinned_cert_sha256)],
    }


def proxy_for_probe(case_id: str, proxy: dict[str, object], skip_cert_verify: bool) -> dict[str, object]:
    if not skip_cert_verify:
        return proxy
    if case_id in TLS_CASES:
        if proxy.get("skip-cert-verify") is not True:
            raise PanelAcceptanceError("panel did not persist the requested TLS client verification override")
        return proxy
    if case_id in WSS_CASES:
        # WSS TLS terminates in Nginx, while the managed Xray inbound remains
        # security=none. Relax only the disposable local probe client.
        temporary_proxy = dict(proxy)
        temporary_proxy["skip-cert-verify"] = True
        return temporary_proxy
    return proxy


def proxy_with_connect_host(proxy: dict[str, object], connect_host: str) -> dict[str, object]:
    if not connect_host:
        return proxy
    temporary_proxy = dict(proxy)
    temporary_proxy["server"] = connect_host
    return temporary_proxy


def node_response_field(node: dict[str, object], snake_case: str, pascal_case: str) -> object | None:
    if snake_case in node:
        return node[snake_case]
    return node.get(pascal_case)


def validate_readback(api: PanelAPI, server_id: int, tag: str, response: object) -> tuple[int, dict[str, object]]:
    if not isinstance(response, dict) or response.get("success") is not True:
        raise PanelAcceptanceError("create response did not confirm success")
    node = response.get("node")
    if not isinstance(node, dict) or node_response_field(node, "inbound_tag", "InboundTag") != tag:
        raise PanelAcceptanceError("created node response does not match requested tag")
    try:
        raw_node_id = response.get("node_id") or node_response_field(node, "id", "ID")
        node_id = int(raw_node_id)
        raw_proxy = node_response_field(node, "clash_config", "ClashConfig")
        proxy = dict(raw_proxy) if isinstance(raw_proxy, dict) else json.loads(str(raw_proxy or ""))
    except (TypeError, ValueError, json.JSONDecodeError) as reason:
        raise PanelAcceptanceError("created node has no valid persisted Clash configuration") from reason
    if node_id <= 0 or not isinstance(proxy, dict):
        raise PanelAcceptanceError("created node has no valid persisted Clash configuration")
    if not remote_tag_exists(api, server_id, tag):
        raise PanelAcceptanceError("created tag was not present in remote inbound readback")
    return node_id, proxy


def remote_tags(api: PanelAPI, server_id: int) -> set[str]:
    response = api.request("GET", f"/api/admin/remote/inbounds?server_id={server_id}")
    if not isinstance(response, dict) or not isinstance(response.get("inbounds"), list):
        raise PanelAcceptanceError("remote inbound readback returned invalid data")
    return {
        str(row["tag"])
        for row in response["inbounds"]
        if isinstance(row, dict) and isinstance(row.get("tag"), str) and row["tag"]
    }


def remote_tag_exists(api: PanelAPI, server_id: int, tag: str) -> bool:
    return tag in remote_tags(api, server_id)


def run_proxy_probe(xray_bin: str, curl_bin: str, work_dir: Path, case_id: str,
                    proxy: dict[str, object], probe_url: str, expected_exit_ip: str, timeout: float,
                    skip_cert_verify: bool = False, pinned_cert_sha256: str = "",
                    connect_host: str = "") -> None:
    socks_port = local_acceptance.reserve_ports(1)[0]
    probe_proxy = proxy_with_connect_host(
        proxy_for_probe(case_id, proxy, skip_cert_verify), connect_host,
    )
    config = build_client_config(
        probe_proxy, socks_port, pinned_cert_sha256,
    )
    config_path = work_dir / f"{case_id}-client.json"
    local_acceptance.secure_write_json(config_path, config)
    hidden = collect_secrets(config)
    local_acceptance.validate_xray_config(xray_bin, config_path, hidden, timeout)
    process = local_acceptance.XrayProcess(xray_bin, config_path)
    try:
        local_acceptance.wait_for_listener(LOOPBACK, socks_port, process, timeout)
        result = subprocess.run(
            [curl_bin, "--silent", "--show-error", "--fail-with-body", "--max-time", str(timeout),
             "--noproxy", "", "--proxy", f"socks5h://{LOOPBACK}:{socks_port}", probe_url],
            capture_output=True, text=True, timeout=timeout + 2, check=False,
        )
        if result.returncode != 0:
            raise PanelAcceptanceError("HTTP request through deployed protocol failed: " + local_acceptance.redact(result.stderr, hidden))
        observed = result.stdout.strip()
        if not observed:
            raise PanelAcceptanceError("HTTP probe returned an empty response")
        if expected_exit_ip:
            try:
                expected, actual = ipaddress.ip_address(expected_exit_ip), ipaddress.ip_address(observed)
            except ValueError as reason:
                raise PanelAcceptanceError("probe response was not the expected IP address") from reason
            if actual != expected:
                raise PanelAcceptanceError(f"probe observed exit {actual}, expected {expected}")
    finally:
        process.close()


def cleanup_tag(api: PanelAPI, server_id: int, tag: str, prefix: str) -> None:
    require_owned_tag(tag, prefix)
    response = api.request("POST", f"/api/admin/remote/inbounds?server_id={server_id}", {"action": "remove", "tag": tag})
    if not isinstance(response, dict) or response.get("success") is not True:
        raise PanelAcceptanceError("remote inbound removal was not confirmed")


def parse_cases(values: list[str]) -> list[str]:
    cases = list(values or DEFAULT_CASES)
    unknown = sorted(set(cases).difference(DEFAULT_CASES))
    if unknown:
        raise PanelAcceptanceError("unknown case(s): " + ", ".join(unknown))
    return list(dict.fromkeys(cases))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--base-url", required=True)
    result.add_argument("--server-id", type=int, required=True)
    result.add_argument("--case", action="append", choices=DEFAULT_CASES, default=[])
    result.add_argument("--port-base", type=int, default=39100)
    result.add_argument("--certificate-id", type=int)
    result.add_argument("--tls-domain", default="")
    result.add_argument("--wss-domain", default="")
    result.add_argument("--reality-domain", default="www.cloudflare.com")
    result.add_argument("--probe-url", default="https://api.ipify.org")
    result.add_argument("--expected-exit-ip", default="")
    result.add_argument(
        "--connect-host",
        default="",
        help="connect the disposable probe to this IP while preserving TLS SNI and WebSocket Host",
    )
    result.add_argument(
        "--skip-cert-verify",
        action="store_true",
        help="allow only disposable protocol clients to accept a self-signed node certificate",
    )
    result.add_argument(
        "--cert-sha256",
        default="",
        help="SHA-256 fingerprint used to pin a disposable self-signed certificate in Xray 26.3.27",
    )
    result.add_argument("--run-id")
    result.add_argument("--token-env", default=DEFAULT_TOKEN_ENV)
    result.add_argument("--ca-file")
    result.add_argument("--xray-bin")
    result.add_argument("--curl-bin")
    result.add_argument("--timeout", type=float, default=20.0)
    result.add_argument("--execute", action="store_true")
    cleanup = result.add_mutually_exclusive_group()
    cleanup.add_argument("--cleanup", action="store_true", help="explicit cleanup request (also the default)")
    cleanup.add_argument("--keep", action="store_true")
    result.add_argument("--fail-fast", action="store_true")
    return result


def validate_args(args: argparse.Namespace, cases: list[str]) -> None:
    parsed = urllib.parse.urlsplit(args.base_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.path.rstrip("/"):
        raise PanelAcceptanceError("--base-url must be an HTTPS origin without a path")
    if args.server_id <= 0:
        raise PanelAcceptanceError("--server-id must be positive")
    if args.port_base < 1024 or args.port_base + len(cases) > 65535:
        raise PanelAcceptanceError("requested port range must stay within 1024-65535")
    if args.timeout < 2:
        raise PanelAcceptanceError("--timeout must be at least 2 seconds")
    if set(cases) & TLS_CASES and (not args.certificate_id or not args.tls_domain):
        raise PanelAcceptanceError("selected TLS cases require --certificate-id and --tls-domain")
    if set(cases) & WSS_CASES and not args.wss_domain:
        raise PanelAcceptanceError("selected WSS cases require --wss-domain")
    args.connect_host = args.connect_host.strip()
    if args.connect_host:
        try:
            ipaddress.ip_address(args.connect_host)
        except ValueError as reason:
            raise PanelAcceptanceError("--connect-host must be an IPv4 or IPv6 address") from reason
    args.cert_sha256 = args.cert_sha256.strip().lower()
    if args.cert_sha256 and not re.fullmatch(r"[0-9a-f]{64}", args.cert_sha256):
        raise PanelAcceptanceError("--cert-sha256 must be 64 hexadecimal characters")
    if args.skip_cert_verify and set(cases) & (TLS_CASES | WSS_CASES) and not args.cert_sha256:
        raise PanelAcceptanceError("Xray 26.3.27 requires --cert-sha256 with --skip-cert-verify")


def run(args: argparse.Namespace) -> int:
    cases = parse_cases(args.case)
    validate_args(args, cases)
    run_id = safe_run_id(args.run_id)
    prefix = tag_prefix(run_id)
    cleanup_enabled = not args.keep
    print(f"Run {run_id}: {len(cases)} case(s), server {args.server_id}, tags {prefix}*")
    if not args.execute:
        print("DRY RUN: no API request was sent; add --execute after reviewing the parameters")
        return 0
    token = os.environ.get(args.token_env, "").strip()
    if not token:
        raise PanelAcceptanceError(f"authentication token is missing from environment variable {args.token_env}")
    xray_bin = local_acceptance.resolve_executable(args.xray_bin, "ARCWAY_ACCEPTANCE_XRAY_BIN", "xray")
    curl_bin = local_acceptance.resolve_executable(args.curl_bin, "ARCWAY_ACCEPTANCE_CURL_BIN", "curl")
    local_acceptance.check_xray_version(xray_bin, EXPECTED_XRAY_VERSION)
    api = PanelAPI(args.base_url, token, args.timeout, args.ca_file)
    planned_tags = {prefix + case_id for case_id in cases}
    collisions = sorted(planned_tags.intersection(remote_tags(api, args.server_id)))
    if collisions:
        raise PanelAcceptanceError("refusing to reuse existing inbound tag(s): " + ", ".join(collisions))
    reality_keys: tuple[str, str] | None = None
    if set(cases) & REALITY_CASES:
        generated = api.request("POST", "/api/admin/xray/generate-x25519", {})
        if not isinstance(generated, dict):
            raise PanelAcceptanceError("X25519 endpoint returned invalid data")
        reality_keys = str(generated.get("privateKey", "")), str(generated.get("publicKey", ""))
        if not all(re.fullmatch(r"[A-Za-z0-9_-]{43}", item) for item in reality_keys):
            raise PanelAcceptanceError("X25519 endpoint returned invalid keys")

    failures: list[tuple[str, str]] = []
    created: list[tuple[str, str, int]] = []
    with tempfile.TemporaryDirectory(prefix="arcway-panel-acceptance-") as temporary:
        work_dir = Path(temporary)
        os.chmod(work_dir, 0o700)
        try:
            for index, case_id in enumerate(cases):
                tag = prefix + case_id
                request: dict[str, object] = {}
                try:
                    tag, request = build_create_request(
                        case_id, prefix, args.port_base + index, args.certificate_id,
                        args.tls_domain.strip().lower(), args.wss_domain.strip().lower(),
                        args.reality_domain.strip().lower(), reality_keys, args.skip_cert_verify,
                    )
                    response = api.request("POST", f"/api/admin/managed-nodes/create?server_id={args.server_id}", request)
                    if isinstance(response, dict) and response.get("success") is True:
                        raw_node = response.get("node")
                        raw_node_id = response.get("node_id") or (
                            node_response_field(raw_node, "id", "ID") if isinstance(raw_node, dict) else 0
                        )
                        node_id_text = str(raw_node_id or "")
                        created.append((case_id, tag, int(node_id_text) if node_id_text.isdigit() else 0))
                    node_id, proxy = validate_readback(api, args.server_id, tag, response)
                    created[-1] = (case_id, tag, node_id)
                    run_proxy_probe(
                        xray_bin, curl_bin, work_dir, case_id, proxy, args.probe_url,
                        args.expected_exit_ip, args.timeout, args.skip_cert_verify, args.cert_sha256,
                        args.connect_host,
                    )
                    print(f"PASS {case_id}: node {node_id}, inbound readback and HTTP proxy verified")
                except Exception as reason:
                    if not any(item[1] == tag for item in created):
                        try:
                            if remote_tag_exists(api, args.server_id, tag):
                                print(
                                    f"UNCONFIRMED {case_id}: tag exists but creation was not confirmed; "
                                    "left untouched for manual review",
                                    file=sys.stderr,
                                )
                        except Exception:
                            pass
                    redacted = local_acceptance.redact(str(reason), collect_secrets(request) + list(reality_keys or ()))
                    message = re.sub(r"\s+", " ", redacted).strip()[:600]
                    failures.append((case_id, message))
                    print(f"FAIL {case_id}: {message}", file=sys.stderr)
                    if args.fail_fast:
                        break
        finally:
            if cleanup_enabled:
                for case_id, tag, _node_id in reversed(created):
                    try:
                        cleanup_tag(api, args.server_id, tag, prefix)
                        print(f"CLEAN {case_id}: disposable inbound removed")
                    except Exception as reason:
                        message = re.sub(r"\s+", " ", str(reason)).strip()[:600]
                        failures.append((case_id + " cleanup", message))
                        print(f"FAIL {case_id} cleanup: {message}", file=sys.stderr)
            elif created:
                print(f"KEEP: {len(created)} disposable resource(s) remain under tag prefix {prefix}")
    if failures:
        print(f"FAILED: {len(failures)} failure(s); no pre-existing tag was eligible for cleanup", file=sys.stderr)
        return 1
    print(f"PASSED: {len(created)} of {len(cases)} case(s); cleanup={'complete' if cleanup_enabled else 'disabled'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return run(args)
    except (PanelAcceptanceError, local_acceptance.AcceptanceError) as reason:
        print(f"ERROR: {reason}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("INTERRUPTED: cleanup was attempted for every confirmed run tag", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
