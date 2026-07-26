from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest

SCRIPT_PATH = Path(__file__).with_name("panel_protocol_connectivity_acceptance.py")
SPEC = importlib.util.spec_from_file_location("panel_protocol_connectivity_acceptance", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
panel = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = panel
SPEC.loader.exec_module(panel)


class FakeAPI:
    def __init__(self, tag: str) -> None:
        self.tag = tag
        self.requests: list[tuple[str, str, object | None]] = []

    def request(self, method: str, path: str, body: object | None = None) -> object:
        self.requests.append((method, path, body))
        return {"success": True, "inbounds": [{"tag": self.tag}]}


class PanelProtocolAcceptanceTest(unittest.TestCase):
    def test_manifest_is_standard_matrix_without_special_cases(self) -> None:
        self.assertEqual(19, len(panel.DEFAULT_CASES))
        self.assertNotIn("wireguard", panel.DEFAULT_CASES)
        self.assertNotIn("anydoor", panel.DEFAULT_CASES)

    def test_all_create_requests_match_managed_api_shape(self) -> None:
        prefix = "accept-unit01-"
        keys = ("A" * 43, "B" * 43)
        for index, case_id in enumerate(panel.DEFAULT_CASES):
            with self.subTest(case=case_id):
                tag, request = panel.build_create_request(
                    case_id, prefix, 39000 + index, 1, "tls.example.com",
                    "wss.example.com", "reality.example.com", keys,
                )
                self.assertEqual(prefix + case_id, tag)
                self.assertEqual("add", request["action"])
                self.assertEqual(tag, request["inbound"]["tag"])
                self.assertNotIn("client_options", request)
                reality = request["inbound"].get("streamSettings", {}).get("realitySettings", {})
                self.assertNotIn("publicKey", reality)
                json.dumps(request)

    def test_skip_cert_verify_is_explicit_and_client_only(self) -> None:
        _tag, request = panel.build_create_request(
            "trojan", "accept-unit01-", 39000, 1, "tls.example.com", "", "", None, True,
        )
        self.assertEqual({"skip_cert_verify": True}, request["client_options"])
        tls = request["inbound"]["streamSettings"]["tlsSettings"]
        self.assertNotIn("allowInsecure", tls)

    def test_clash_converter_supports_every_standard_family(self) -> None:
        base = {"server": "192.0.2.1", "port": 39000}
        proxies = [
            {**base, "type": "vless", "uuid": "11111111-1111-4111-8111-111111111111", "network": "tcp"},
            {**base, "type": "vmess", "uuid": "11111111-1111-4111-8111-111111111111", "cipher": "auto"},
            {**base, "type": "trojan", "password": "secret-value", "tls": True, "sni": "tls.example.com"},
            {**base, "type": "ss", "cipher": "aes-128-gcm", "password": "secret-value"},
            {**base, "type": "hysteria2", "password": "secret-value", "sni": "tls.example.com"},
            {**base, "type": "socks", "username": "acceptance", "password": "secret-value"},
            {**base, "type": "http", "username": "acceptance", "password": "secret-value"},
        ]
        for proxy in proxies:
            with self.subTest(proxy=proxy["type"]):
                config = panel.build_client_config(proxy, 39099)
                self.assertEqual("socks", config["inbounds"][0]["protocol"])
                json.dumps(config)

    def test_reality_converter_uses_xray_26327_password_field(self) -> None:
        outbound = panel.clash_to_xray_outbound({
            "type": "vless", "server": "192.0.2.1", "port": 443,
            "uuid": "11111111-1111-4111-8111-111111111111", "network": "tcp",
            "servername": "reality.example.com",
            "reality-opts": {"public-key": "B" * 43, "short-id": "0123456789abcdef"},
        })
        reality = outbound["streamSettings"]["realitySettings"]
        self.assertEqual("B" * 43, reality["password"])
        self.assertNotIn("publicKey", reality)

    def test_tls_converter_pins_self_signed_certificate_without_allow_insecure(self) -> None:
        fingerprint = "01" * 32
        outbound = panel.clash_to_xray_outbound({
            "type": "trojan", "server": "192.0.2.1", "port": 443,
            "password": "secret-value", "tls": True, "sni": "tls.example.com",
            "skip-cert-verify": True,
        }, fingerprint)
        tls = outbound["streamSettings"]["tlsSettings"]
        self.assertEqual(fingerprint, tls["pinnedPeerCertSha256"])
        self.assertNotIn("allowInsecure", tls)

    def test_skip_verify_requires_certificate_fingerprint(self) -> None:
        args = panel.parser().parse_args([
            "--base-url", "https://panel.example", "--server-id", "1",
            "--case", "trojan", "--certificate-id", "2", "--tls-domain", "tls.example.com",
            "--skip-cert-verify",
        ])
        with self.assertRaises(panel.PanelAcceptanceError):
            panel.validate_args(args, ["trojan"])

    def test_connect_host_overrides_only_transport_address(self) -> None:
        proxy = {
            "type": "trojan", "server": "tls.example.com", "port": 443,
            "password": "secret-value", "tls": True, "sni": "tls.example.com",
        }
        probe_proxy = panel.proxy_with_connect_host(proxy, "192.0.2.10")
        outbound = panel.clash_to_xray_outbound(probe_proxy)
        self.assertEqual("192.0.2.10", outbound["settings"]["servers"][0]["address"])
        self.assertEqual("tls.example.com", outbound["streamSettings"]["tlsSettings"]["serverName"])
        self.assertEqual("tls.example.com", proxy["server"])

    def test_connect_host_must_be_an_ip_literal(self) -> None:
        args = panel.parser().parse_args([
            "--base-url", "https://panel.example", "--server-id", "1",
            "--case", "vless-ws", "--connect-host", "https://192.0.2.10",
        ])
        with self.assertRaises(panel.PanelAcceptanceError):
            panel.validate_args(args, ["vless-ws"])

    def test_validate_readback_accepts_production_go_struct_fields(self) -> None:
        tag = "accept-unit01-vless-ws"
        api = FakeAPI(tag)
        node_id, proxy = panel.validate_readback(api, 7, tag, {
            "success": True,
            "node_id": 42,
            "node": {
                "ID": 42,
                "InboundTag": tag,
                "ClashConfig": json.dumps({"type": "vless", "server": "192.0.2.1", "port": 443}),
            },
        })
        self.assertEqual(42, node_id)
        self.assertEqual("vless", proxy["type"])

    def test_validate_readback_accepts_json_tagged_fields(self) -> None:
        tag = "accept-unit01-vmess"
        api = FakeAPI(tag)
        node_id, proxy = panel.validate_readback(api, 7, tag, {
            "success": True,
            "node": {
                "id": 43,
                "inbound_tag": tag,
                "clash_config": json.dumps({"type": "vmess", "server": "192.0.2.2", "port": 8443}),
            },
        })
        self.assertEqual(43, node_id)
        self.assertEqual("vmess", proxy["type"])

    def test_cleanup_refuses_tag_outside_this_run(self) -> None:
        api = FakeAPI("accept-unit01-vless-ws")
        with self.assertRaises(panel.PanelAcceptanceError):
            panel.cleanup_tag(api, 1, "existing-production-tag", "accept-unit01-")
        self.assertEqual([], api.requests)

    def test_cleanup_uses_remote_inbound_remove(self) -> None:
        tag = "accept-unit01-vless-ws"
        api = FakeAPI(tag)
        panel.cleanup_tag(api, 7, tag, "accept-unit01-")
        self.assertEqual(
            ("POST", "/api/admin/remote/inbounds?server_id=7", {"action": "remove", "tag": tag}),
            api.requests[0],
        )

    def test_dry_run_needs_no_token_and_makes_no_request(self) -> None:
        exit_code = panel.main([
            "--base-url", "https://panel.example", "--server-id", "1",
            "--case", "vless-ws", "--run-id", "unit01",
        ])
        self.assertEqual(0, exit_code)

    def test_secure_writer_reused_by_panel_runner_is_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "client.json"
            panel.local_acceptance.secure_write_json(path, {"password": "secret-value"})
            self.assertEqual(stat.S_IRUSR | stat.S_IWUSR, stat.S_IMODE(path.stat().st_mode))


if __name__ == "__main__":
    unittest.main()
