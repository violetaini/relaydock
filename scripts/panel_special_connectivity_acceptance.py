#!/usr/bin/env python3
"""Verify disposable panel-managed WireGuard and AnyDoor resources.

The runner is a dry run unless --execute is present. It reads the admin token
only from an environment variable and always attempts exact cleanup for the
unique tags owned by the current run.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse


PANEL_RUNNER_PATH = Path(__file__).with_name("panel_protocol_connectivity_acceptance.py")
PANEL_SPEC = importlib.util.spec_from_file_location("arcway_panel_acceptance", PANEL_RUNNER_PATH)
if PANEL_SPEC is None or PANEL_SPEC.loader is None:
    raise RuntimeError("cannot load panel_protocol_connectivity_acceptance.py")
panel_acceptance = importlib.util.module_from_spec(PANEL_SPEC)
sys.modules[PANEL_SPEC.name] = panel_acceptance
PANEL_SPEC.loader.exec_module(panel_acceptance)

PanelAPI = panel_acceptance.PanelAPI
PanelAcceptanceError = panel_acceptance.PanelAcceptanceError
local_acceptance = panel_acceptance.local_acceptance
DEFAULT_TOKEN_ENV = panel_acceptance.DEFAULT_TOKEN_ENV
EXPECTED_XRAY_VERSION = panel_acceptance.EXPECTED_XRAY_VERSION
LOOPBACK = panel_acceptance.LOOPBACK
CASES = ("wireguard", "anydoor")


def special_run_id(value: str | None = None) -> str:
    return panel_acceptance.safe_run_id(value)


def wireguard_tag(run_id: str) -> str:
    return f"accept-{run_id}-wireguard"


def chain_label(run_id: str) -> str:
    readable = re.sub(r"[^a-z0-9-]", "", run_id.lower()).strip("-")[:16] or "run"
    digest = hashlib.sha256(run_id.encode("ascii")).hexdigest()[:8]
    label = f"accept-{readable}-{digest}"
    if not re.fullmatch(r"[a-z0-9-]{2,32}", label):
        raise PanelAcceptanceError("could not derive a safe AnyDoor label")
    return label


def chain_tag(label: str, index: int) -> str:
    return f"tunnel-{label}-h{index}"


def require_wireguard_tag(tag: str, expected: str) -> None:
    if tag != expected or not re.fullmatch(r"accept-[a-z0-9-]+-wireguard", tag):
        raise PanelAcceptanceError("refusing WireGuard cleanup outside this run")


def require_chain_tag(tag: str, label: str, index: int) -> None:
    if not re.fullmatch(r"accept-[a-z0-9-]{2,25}", label) or tag != chain_tag(label, index):
        raise PanelAcceptanceError("refusing AnyDoor cleanup outside this run")


def parse_cases(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values or CASES))


def remote_inbounds(api: PanelAPI, server_id: int) -> list[dict[str, object]]:
    response = api.request("GET", f"/api/admin/remote/inbounds?server_id={server_id}")
    if not isinstance(response, dict) or not isinstance(response.get("inbounds"), list):
        raise PanelAcceptanceError("remote inbound readback returned invalid data")
    return [dict(item) for item in response["inbounds"] if isinstance(item, dict)]


def remote_inbound(api: PanelAPI, server_id: int, tag: str) -> dict[str, object] | None:
    matches = [item for item in remote_inbounds(api, server_id) if item.get("tag") == tag]
    if len(matches) > 1:
        raise PanelAcceptanceError(f"remote server {server_id} returned duplicate tag {tag}")
    return matches[0] if matches else None


def managed_resources(api: PanelAPI) -> list[dict[str, object]]:
    response = api.request("GET", "/api/admin/managed-inbound-resources")
    if not isinstance(response, dict) or not isinstance(response.get("resources"), list):
        raise PanelAcceptanceError("managed inbound resource list returned invalid data")
    return [dict(item) for item in response["resources"] if isinstance(item, dict)]


def matching_wireguard_resources(api: PanelAPI, server_id: int, tag: str) -> list[dict[str, object]]:
    return [
        item for item in managed_resources(api)
        if item.get("server_id") == server_id and item.get("inbound_tag") == tag
    ]


def parse_metadata(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as reason:
            raise PanelAcceptanceError("WireGuard public metadata is invalid JSON") from reason
        if isinstance(parsed, dict):
            return dict(parsed)
    raise PanelAcceptanceError("WireGuard resource has no public metadata")


def wireguard_addresses(run_id: str) -> tuple[str, str]:
    digest = hashlib.sha256(("wireguard:" + run_id).encode("ascii")).digest()
    second = 200 + digest[0] % 40
    third = 1 + digest[1] % 253
    return f"10.{second}.{third}.1/32", f"10.{second}.{third}.2/32"


def build_wireguard_request(
    tag: str,
    port: int,
    server_private: str,
    client_public: str,
    server_address: str,
    client_address: str,
) -> dict[str, object]:
    return {
        "action": "add",
        "display_name": "Acceptance WireGuard",
        "inbound": {
            "tag": tag,
            "listen": "0.0.0.0",
            "port": port,
            "protocol": "wireguard",
            "settings": {
                "secretKey": server_private,
                "address": [server_address],
                "mtu": 1420,
                "noKernelTun": False,
                "peers": [{
                    "publicKey": client_public,
                    "allowedIPs": [client_address],
                    "keepAlive": 25,
                }],
            },
            "sniffing": {"enabled": False},
        },
    }


def endpoint_text(host: str, port: int) -> str:
    normalized = host.strip()
    if ":" in normalized and not normalized.startswith("["):
        normalized = f"[{normalized}]"
    return f"{normalized}:{port}"


def build_wireguard_client(
    endpoint_host: str,
    endpoint_port: int,
    client_private: str,
    server_public: str,
    client_address: str,
    socks_port: int,
    udp_port: int,
    dns_server: str,
) -> dict[str, object]:
    return {
        "log": {"loglevel": "none"},
        "inbounds": [
            {
                "tag": "acceptance-socks",
                "listen": LOOPBACK,
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": False},
            },
            {
                "tag": "acceptance-udp-dns",
                "listen": LOOPBACK,
                "port": udp_port,
                "protocol": "tunnel",
                "settings": {
                    "address": dns_server,
                    "port": 53,
                    "network": "udp",
                    "followRedirect": False,
                },
            },
        ],
        "outbounds": [{
            "tag": "tested-wireguard",
            "protocol": "wireguard",
            "settings": {
                "secretKey": client_private,
                "address": [client_address],
                "mtu": 1420,
                "noKernelTun": True,
                "domainStrategy": "ForceIPv4",
                "peers": [{
                    "publicKey": server_public,
                    "endpoint": endpoint_text(endpoint_host, endpoint_port),
                    "allowedIPs": ["0.0.0.0/0"],
                    "keepAlive": 25,
                }],
            },
        }],
    }


def dns_query(name: str = "example.com") -> tuple[int, bytes]:
    transaction_id = secrets.randbelow(65536)
    labels = name.rstrip(".").split(".")
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"
    return transaction_id, struct.pack("!HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0) + question + struct.pack("!HH", 1, 1)


def probe_dns(port: int, timeout: float) -> None:
    transaction_id, query = dns_query()
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(min(1.0, max(0.1, deadline - time.monotonic())))
            try:
                client.sendto(query, (LOOPBACK, port))
                response, _ = client.recvfrom(65535)
                if len(response) < 12:
                    raise PanelAcceptanceError("UDP DNS response was truncated")
                response_id, flags, _questions, answers, _authority, _additional = struct.unpack("!HHHHHH", response[:12])
                if response_id != transaction_id or flags & 0x8000 == 0:
                    raise PanelAcceptanceError("UDP DNS response did not match the request")
                if flags & 0x000F:
                    raise PanelAcceptanceError(f"UDP DNS response returned rcode {flags & 0x000F}")
                if answers < 1:
                    raise PanelAcceptanceError("UDP DNS response contained no answer")
                return
            except (OSError, PanelAcceptanceError) as reason:
                last_error = reason
                time.sleep(0.1)
    raise PanelAcceptanceError("UDP DNS request through WireGuard timed out") from last_error


def probe_http_through_socks(
    curl_bin: str,
    socks_port: int,
    probe_url: str,
    expected_exit_ip: str,
    timeout: float,
) -> None:
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
            probe_url,
        ],
        capture_output=True,
        text=True,
        timeout=timeout + 2,
        check=False,
    )
    if result.returncode != 0:
        raise PanelAcceptanceError("TCP HTTP request through WireGuard failed: " + local_acceptance.redact(result.stderr, []))
    observed = result.stdout.strip()
    try:
        actual = ipaddress.ip_address(observed)
    except ValueError as reason:
        raise PanelAcceptanceError("WireGuard HTTP probe did not return an IP address") from reason
    if expected_exit_ip and actual != ipaddress.ip_address(expected_exit_ip):
        raise PanelAcceptanceError(f"WireGuard probe observed exit {actual}, expected {expected_exit_ip}")


def validate_wireguard_response(
    api: PanelAPI,
    response: object,
    server_id: int,
    tag: str,
    port: int,
    server_public: str,
) -> tuple[int, str]:
    if not isinstance(response, dict) or response.get("success") is not True or not isinstance(response.get("resource"), dict):
        raise PanelAcceptanceError("WireGuard create response did not confirm a managed resource")
    resource = dict(response["resource"])
    try:
        resource_id = int(resource.get("id", 0))
        resource_server_id = int(resource.get("server_id", 0))
        endpoint_port = int(resource.get("endpoint_port", 0))
    except (TypeError, ValueError) as reason:
        raise PanelAcceptanceError("WireGuard resource identifiers are invalid") from reason
    if resource_id <= 0 or resource_server_id != server_id or resource.get("inbound_tag") != tag:
        raise PanelAcceptanceError("WireGuard resource does not match the requested server and tag")
    if resource.get("protocol") != "wireguard" or endpoint_port != port:
        raise PanelAcceptanceError("WireGuard resource protocol or endpoint port does not match")
    metadata = parse_metadata(resource.get("public_metadata"))
    if metadata.get("server_public_key") != server_public:
        raise PanelAcceptanceError("WireGuard resource public key does not match the generated server key")
    endpoint_host = str(resource.get("endpoint_host", "")).strip()
    if not endpoint_host:
        raise PanelAcceptanceError("WireGuard resource has no reachable endpoint host")
    inbound = remote_inbound(api, server_id, tag)
    if inbound is None or str(inbound.get("protocol", "")).lower() != "wireguard" or int(inbound.get("port", 0)) != port:
        raise PanelAcceptanceError("WireGuard Agent readback does not match the created resource")
    return resource_id, endpoint_host


def remove_raw_inbound(api: PanelAPI, server_id: int, tag: str) -> None:
    response = api.request(
        "POST",
        f"/api/admin/remote/inbounds?server_id={server_id}",
        {"action": "remove", "tag": tag},
    )
    if not isinstance(response, dict) or response.get("success") is not True:
        raise PanelAcceptanceError(f"server {server_id} did not confirm removal of {tag}")


def cleanup_wireguard(api: PanelAPI, server_id: int, tag: str, expected_tag: str) -> None:
    require_wireguard_tag(tag, expected_tag)
    resources = matching_wireguard_resources(api, server_id, tag)
    if len(resources) > 1:
        raise PanelAcceptanceError("refusing cleanup because duplicate WireGuard resource records exist")
    if resources:
        try:
            resource_id = int(resources[0].get("id", 0))
        except (TypeError, ValueError) as reason:
            raise PanelAcceptanceError("WireGuard cleanup resource ID is invalid") from reason
        if resource_id <= 0:
            raise PanelAcceptanceError("WireGuard cleanup resource ID is invalid")
        response = api.request("DELETE", f"/api/admin/managed-inbound-resources/{resource_id}")
        if not isinstance(response, dict) or response.get("success") is not True:
            raise PanelAcceptanceError("managed WireGuard deletion was not confirmed")
    if remote_inbound(api, server_id, tag) is not None:
        remove_raw_inbound(api, server_id, tag)
    if remote_inbound(api, server_id, tag) is not None or matching_wireguard_resources(api, server_id, tag):
        raise PanelAcceptanceError("WireGuard cleanup verification failed")


def run_wireguard(args: argparse.Namespace, api: PanelAPI, run_id: str, xray_bin: str, curl_bin: str) -> None:
    tag = wireguard_tag(run_id)
    if remote_inbound(api, args.wireguard_server_id, tag) is not None:
        raise PanelAcceptanceError(f"refusing to reuse existing WireGuard tag {tag}")
    if matching_wireguard_resources(api, args.wireguard_server_id, tag):
        raise PanelAcceptanceError(f"refusing to reuse existing WireGuard resource {tag}")

    server_private, server_public = local_acceptance.generate_x25519_keys(xray_bin, standard_encoding=True)
    client_private, client_public = local_acceptance.generate_x25519_keys(xray_bin, standard_encoding=True)
    server_address, client_address = wireguard_addresses(run_id)
    request = build_wireguard_request(
        tag,
        args.wireguard_port,
        server_private,
        client_public,
        server_address,
        client_address,
    )
    hidden = [server_private, server_public, client_private, client_public]
    attempted = False
    primary_error: Exception | None = None
    try:
        attempted = True
        response = api.request(
            "POST",
            f"/api/admin/managed-inbound-resources/wireguard?server_id={args.wireguard_server_id}",
            request,
        )
        _resource_id, endpoint_host = validate_wireguard_response(
            api, response, args.wireguard_server_id, tag, args.wireguard_port, server_public,
        )
        socks_port = local_acceptance.reserve_ports(1)[0]
        udp_port = local_acceptance.reserve_ports(1, socket.SOCK_DGRAM)[0]
        config = build_wireguard_client(
            endpoint_host,
            args.wireguard_port,
            client_private,
            server_public,
            client_address,
            socks_port,
            udp_port,
            args.dns_server,
        )
        with tempfile.TemporaryDirectory(prefix="arcway-panel-wireguard-") as temporary:
            work_dir = Path(temporary)
            os.chmod(work_dir, 0o700)
            config_path = work_dir / "wireguard-client.json"
            local_acceptance.secure_write_json(config_path, config)
            local_acceptance.validate_xray_config(xray_bin, config_path, hidden, args.timeout)
            process = local_acceptance.XrayProcess(xray_bin, config_path)
            try:
                local_acceptance.wait_for_listener(LOOPBACK, socks_port, process, args.timeout)
                probe_http_through_socks(curl_bin, socks_port, args.probe_url, args.expected_exit_ip, args.timeout)
                probe_dns(udp_port, args.timeout)
            finally:
                process.close()
        print("PASS wireguard: managed resource, Agent readback, TCP HTTP and inner UDP DNS verified")
    except Exception as reason:
        primary_error = reason
        raise PanelAcceptanceError(local_acceptance.redact(str(reason), hidden)) from reason
    finally:
        if attempted:
            try:
                cleanup_wireguard(api, args.wireguard_server_id, tag, tag)
                print("CLEAN wireguard: disposable managed resource removed")
            except Exception as cleanup_error:
                message = local_acceptance.redact(str(cleanup_error), hidden)
                if primary_error is None:
                    raise PanelAcceptanceError("WireGuard cleanup failed: " + message) from cleanup_error
                print("FAIL wireguard cleanup: " + message, file=sys.stderr)


class EchoProbe:
    """Small, non-amplifying TCP/UDP echo target for the final AnyDoor hop."""

    def __init__(self, bind_host: str, port: int) -> None:
        self.stop_event = threading.Event()
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for listener in (self.tcp, self.udp):
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.tcp.bind((bind_host, port))
            self.udp.bind((bind_host, int(self.tcp.getsockname()[1])))
            self.tcp.listen(16)
            self.tcp.settimeout(0.2)
            self.udp.settimeout(0.2)
        except Exception:
            self.tcp.close()
            self.udp.close()
            raise
        self.port = int(self.tcp.getsockname()[1])
        self.threads = [
            threading.Thread(target=self._serve_tcp, name="arcway-anydoor-tcp", daemon=True),
            threading.Thread(target=self._serve_udp, name="arcway-anydoor-udp", daemon=True),
        ]

    def start(self) -> None:
        for thread in self.threads:
            thread.start()

    def _serve_tcp(self) -> None:
        while not self.stop_event.is_set():
            try:
                connection, _ = self.tcp.accept()
            except (TimeoutError, OSError):
                continue
            with connection:
                connection.settimeout(2)
                try:
                    while True:
                        chunk = connection.recv(4096)
                        if not chunk:
                            break
                        connection.sendall(chunk)
                except OSError:
                    continue

    def _serve_udp(self) -> None:
        while not self.stop_event.is_set():
            try:
                payload, address = self.udp.recvfrom(4096)
            except (TimeoutError, OSError):
                continue
            if payload:
                try:
                    self.udp.sendto(payload, address)
                except OSError:
                    continue

    def close(self) -> None:
        self.stop_event.set()
        self.tcp.close()
        self.udp.close()
        for thread in self.threads:
            thread.join(timeout=1)


def probe_tcp_echo(host: str, port: int, timeout: float) -> None:
    payload = b"arcway-anydoor-tcp:" + secrets.token_bytes(24)
    with socket.create_connection((host, port), timeout=timeout) as client:
        client.settimeout(timeout)
        client.sendall(payload)
        chunks: list[bytes] = []
        while sum(map(len, chunks)) < len(payload):
            chunk = client.recv(len(payload))
            if not chunk:
                break
            chunks.append(chunk)
    if b"".join(chunks) != payload:
        raise PanelAcceptanceError("TCP echo through AnyDoor did not match the nonce")


def probe_udp_echo(host: str, port: int, timeout: float) -> None:
    payload = b"arcway-anydoor-udp:" + secrets.token_bytes(24)
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    last_error: Exception | None = None
    for family, socket_type, protocol, _canonical, address in addresses:
        with socket.socket(family, socket_type, protocol) as client:
            client.settimeout(timeout)
            try:
                client.sendto(payload, address)
                response, _ = client.recvfrom(4096)
            except OSError as reason:
                last_error = reason
                continue
            if response == payload:
                return
            last_error = PanelAcceptanceError("UDP echo through AnyDoor did not match the nonce")
    raise PanelAcceptanceError("UDP echo through AnyDoor failed") from last_error


def build_chain_request(label: str, server_ids: list[int], port: int, target_host: str) -> dict[str, object]:
    return {
        "label": label,
        "server_ids": server_ids,
        "entry_port": port,
        "target_address": target_host.strip(),
        "target_port": port,
    }


def validate_chain_response(
    api: PanelAPI,
    response: object,
    label: str,
    server_ids: list[int],
    port: int,
    target_host: str,
) -> str:
    if not isinstance(response, dict) or response.get("success") is not True:
        raise PanelAcceptanceError("AnyDoor chain create response did not confirm success")
    if response.get("label") != label or int(response.get("entry_port", 0)) != port:
        raise PanelAcceptanceError("AnyDoor chain response label or shared port does not match")
    hops = response.get("hops")
    if not isinstance(hops, list) or len(hops) != len(server_ids):
        raise PanelAcceptanceError("AnyDoor chain response has an unexpected hop count")
    for index, server_id in enumerate(server_ids):
        hop = hops[index]
        expected_tag = chain_tag(label, index)
        if not isinstance(hop, dict):
            raise PanelAcceptanceError("AnyDoor chain response contains an invalid hop")
        if int(hop.get("server_id", 0)) != server_id or hop.get("tag") != expected_tag:
            raise PanelAcceptanceError("AnyDoor chain response hop identity does not match")
        if int(hop.get("listen_port", 0)) != port:
            raise PanelAcceptanceError("AnyDoor chain did not use one shared port on every server")
        if index == len(server_ids) - 1:
            if hop.get("target_address") != target_host or int(hop.get("target_port", 0)) != port:
                raise PanelAcceptanceError("AnyDoor final hop does not use the same target port")
        inbound = remote_inbound(api, server_id, expected_tag)
        settings = inbound.get("settings") if isinstance(inbound, dict) else None
        network = str(settings.get("network", "")) if isinstance(settings, dict) else ""
        networks = {item.strip() for item in network.split(",") if item.strip()}
        if (
            not isinstance(inbound, dict)
            or str(inbound.get("protocol", "")).lower() != "tunnel"
            or int(inbound.get("port", 0)) != port
            or networks != {"tcp", "udp"}
        ):
            raise PanelAcceptanceError(f"AnyDoor Agent readback for hop {index + 1} is incomplete")
    entry_host = str(response.get("entry_host", "")).strip()
    if not entry_host:
        raise PanelAcceptanceError("AnyDoor response has no reachable entry host")
    return entry_host


def cleanup_chain(api: PanelAPI, server_ids: list[int], label: str) -> None:
    failures: list[str] = []
    for index in reversed(range(len(server_ids))):
        tag = chain_tag(label, index)
        require_chain_tag(tag, label, index)
        try:
            if remote_inbound(api, server_ids[index], tag) is not None:
                remove_raw_inbound(api, server_ids[index], tag)
            if remote_inbound(api, server_ids[index], tag) is not None:
                raise PanelAcceptanceError("tag remains after removal")
        except Exception as reason:
            failures.append(f"server {server_ids[index]} tag {tag}: {reason}")
    if failures:
        raise PanelAcceptanceError("; ".join(failures))


def run_anydoor(args: argparse.Namespace, api: PanelAPI, run_id: str) -> None:
    label = chain_label(run_id)
    planned = [(server_id, chain_tag(label, index)) for index, server_id in enumerate(args.chain_server_id)]
    for server_id, tag in planned:
        if remote_inbound(api, server_id, tag) is not None:
            raise PanelAcceptanceError(f"refusing to reuse existing AnyDoor tag {tag}")

    echo: EchoProbe | None = None
    port = args.anydoor_port
    if args.serve_echo:
        echo = EchoProbe(args.echo_bind_host, port)
        port = echo.port
        echo.start()
    elif port == 0:
        raise PanelAcceptanceError("external AnyDoor echo requires an explicit --anydoor-port")

    target_host = args.target_host.strip()
    request = build_chain_request(label, args.chain_server_id, port, target_host)
    attempted = False
    primary_error: Exception | None = None
    try:
        attempted = True
        response = api.request("POST", "/api/admin/tunnel-chains", request)
        entry_host = validate_chain_response(
            api, response, label, args.chain_server_id, port, target_host,
        )
        probe_tcp_echo(entry_host, port, args.timeout)
        probe_udp_echo(entry_host, port, args.timeout)
        print(f"PASS anydoor: {len(args.chain_server_id)} managed hops and target use port {port}; TCP/UDP echo verified")
    except Exception as reason:
        primary_error = reason
        raise
    finally:
        if attempted:
            try:
                cleanup_chain(api, args.chain_server_id, label)
                print("CLEAN anydoor: every disposable hop removed in reverse order")
            except Exception as cleanup_error:
                if primary_error is None:
                    raise PanelAcceptanceError("AnyDoor cleanup failed: " + str(cleanup_error)) from cleanup_error
                print("FAIL anydoor cleanup: " + str(cleanup_error), file=sys.stderr)
        if echo is not None:
            echo.close()


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--base-url", required=True)
    result.add_argument("--case", action="append", choices=CASES, default=[])
    result.add_argument("--wireguard-server-id", type=int, default=1)
    result.add_argument("--wireguard-port", type=int, default=51920)
    result.add_argument("--chain-server-id", action="append", type=int, default=[])
    result.add_argument("--anydoor-port", type=int, default=0)
    result.add_argument("--target-host", default="")
    result.add_argument("--serve-echo", action="store_true")
    result.add_argument("--echo-bind-host", default="0.0.0.0")
    result.add_argument("--dns-server", default="1.1.1.1")
    result.add_argument("--probe-url", default="https://api.ipify.org")
    result.add_argument("--expected-exit-ip", default="")
    result.add_argument("--run-id")
    result.add_argument("--token-env", default=DEFAULT_TOKEN_ENV)
    result.add_argument("--ca-file")
    result.add_argument("--xray-bin")
    result.add_argument("--curl-bin")
    result.add_argument("--timeout", type=float, default=20.0)
    result.add_argument("--execute", action="store_true")
    return result


def validate_args(args: argparse.Namespace, cases: list[str]) -> None:
    parsed = urllib.parse.urlsplit(args.base_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.path.rstrip("/"):
        raise PanelAcceptanceError("--base-url must be an HTTPS origin without a path")
    if args.timeout < 2:
        raise PanelAcceptanceError("--timeout must be at least 2 seconds")
    if "wireguard" in cases:
        if args.wireguard_server_id <= 0 or not 1024 <= args.wireguard_port <= 65535:
            raise PanelAcceptanceError("WireGuard server ID and port are invalid")
        try:
            ipaddress.ip_address(args.dns_server)
        except ValueError as reason:
            raise PanelAcceptanceError("--dns-server must be an IP literal") from reason
    if "anydoor" in cases:
        if len(args.chain_server_id) < 2 or len(set(args.chain_server_id)) != len(args.chain_server_id):
            raise PanelAcceptanceError("AnyDoor requires at least two distinct --chain-server-id values")
        if any(server_id <= 0 for server_id in args.chain_server_id):
            raise PanelAcceptanceError("AnyDoor server IDs must be positive")
        if not args.target_host.strip():
            raise PanelAcceptanceError("AnyDoor requires --target-host for the TCP/UDP echo server")
        if args.anydoor_port != 0 and not 1024 <= args.anydoor_port <= 65535:
            raise PanelAcceptanceError("--anydoor-port must be 0 or 1024-65535")
        if not args.serve_echo and args.anydoor_port == 0:
            raise PanelAcceptanceError("external AnyDoor echo requires an explicit --anydoor-port")
    if args.expected_exit_ip:
        try:
            ipaddress.ip_address(args.expected_exit_ip)
        except ValueError as reason:
            raise PanelAcceptanceError("--expected-exit-ip must be an IP literal") from reason


def run(args: argparse.Namespace) -> int:
    cases = parse_cases(args.case)
    validate_args(args, cases)
    run_id = special_run_id(args.run_id)
    print(f"Run {run_id}: {', '.join(cases)}; cleanup is mandatory")
    if not args.execute:
        print("DRY RUN: no listener was opened and no API request was sent; add --execute after review")
        return 0
    token = os.environ.get(args.token_env, "").strip()
    if not token:
        raise PanelAcceptanceError(f"authentication token is missing from environment variable {args.token_env}")
    xray_bin = local_acceptance.resolve_executable(args.xray_bin, "ARCWAY_ACCEPTANCE_XRAY_BIN", "xray")
    curl_bin = local_acceptance.resolve_executable(args.curl_bin, "ARCWAY_ACCEPTANCE_CURL_BIN", "curl")
    local_acceptance.check_xray_version(xray_bin, EXPECTED_XRAY_VERSION)
    api = PanelAPI(args.base_url, token, args.timeout, args.ca_file)
    failures: list[tuple[str, str]] = []
    for case_id in cases:
        try:
            if case_id == "wireguard":
                run_wireguard(args, api, run_id, xray_bin, curl_bin)
            else:
                run_anydoor(args, api, run_id)
        except Exception as reason:
            message = re.sub(r"\s+", " ", str(reason)).strip()[:600]
            failures.append((case_id, message))
            print(f"FAIL {case_id}: {message}", file=sys.stderr)
    if failures:
        print(f"FAILED: {len(failures)} case(s); cleanup was attempted for every owned tag", file=sys.stderr)
        return 1
    print(f"PASSED: {len(cases)} of {len(cases)} special case(s); cleanup complete")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return run(args)
    except (PanelAcceptanceError, local_acceptance.AcceptanceError) as reason:
        print(f"ERROR: {reason}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("INTERRUPTED: active case cleanup was attempted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
