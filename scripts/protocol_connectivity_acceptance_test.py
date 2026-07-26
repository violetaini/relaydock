from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import socket
import stat
import sys
import tempfile
import unittest


SCRIPT_PATH = Path(__file__).with_name("protocol_connectivity_acceptance.py")
SPEC = importlib.util.spec_from_file_location("protocol_connectivity_acceptance", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
acceptance = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = acceptance
SPEC.loader.exec_module(acceptance)


EXPECTED_PRESETS = {
    "vless-reality",
    "vless-tls",
    "vless-grpc-tls",
    "vless-ws",
    "vless-wss",
    "vmess",
    "vmess-tls",
    "vmess-grpc-tls",
    "vmess-ws",
    "vmess-wss",
    "trojan",
    "trojan-reality",
    "trojan-grpc-tls",
    "trojan-wss",
    "shadowsocks",
    "hysteria2",
    "socks5",
    "http",
    "wireguard",
    "anydoor",
}


def make_material(directory: Path) -> object:
    credentials = acceptance.Credentials(
        client_uuid="11111111-1111-4111-8111-111111111111",
        password="acceptance-password-value",
        username="arcway-acceptance",
        ss_classic_password="classic-password-value",
        ss2022_master="AAAAAAAAAAAAAAAAAAAAAA==",
        ss2022_user="BBBBBBBBBBBBBBBBBBBBBB==",
        reality_private="C" * 43,
        reality_public="D" * 43,
        reality_short_id="1234567890abcdef",
        wireguard_server_private="E" * 43 + "=",
        wireguard_server_public="F" * 43 + "=",
        wireguard_client_private="G" * 43 + "=",
        wireguard_client_public="H" * 43 + "=",
    )
    return acceptance.Material(
        cert_path=directory / "certificate.pem",
        key_path=directory / "private-key.pem",
        cert_sha256="01" * 32,
        credentials=credentials,
    )


class ProtocolConnectivityAcceptanceTest(unittest.TestCase):
    def test_manifest_covers_every_managed_preset(self) -> None:
        self.assertEqual(EXPECTED_PRESETS, set(acceptance.MANAGED_PRESET_COVERAGE))
        covered = {case.managed_preset for case in acceptance.XRAY_CASES}
        covered.update(acceptance.SPECIAL_CASE_IDS)
        self.assertEqual(EXPECTED_PRESETS, covered)
        self.assertEqual(21, len(acceptance.XRAY_CASES) + len(acceptance.SPECIAL_CASE_IDS))

    def test_every_standard_case_builds_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            material = make_material(Path(temporary))
            for case in acceptance.XRAY_CASES:
                with self.subTest(case=case.case_id):
                    pair = acceptance.build_config_pair(case, material, 10001, 10002, 10003, 10004)
                    json.dumps(pair.server)
                    json.dumps(pair.client)

    def test_tls_clients_use_pin_and_never_allow_insecure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            material = make_material(Path(temporary))
            for case in acceptance.XRAY_CASES:
                pair = acceptance.build_config_pair(case, material, 10001, 10002, 10003, 10004)
                rendered = json.dumps(pair.client)
                self.assertNotIn("allowInsecure", rendered, case.case_id)
                if case.security in {"tls", "wss"}:
                    stream = pair.client["outbounds"][0]["streamSettings"]
                    tls = stream["tlsSettings"]
                    self.assertEqual("01" * 32, tls["pinnedPeerCertSha256"])
                    self.assertEqual(acceptance.TLS_SERVER_NAME, tls["verifyPeerCertByName"])

    def test_wss_uses_external_tls_terminator_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            material = make_material(Path(temporary))
            case = next(item for item in acceptance.XRAY_CASES if item.case_id == "trojan-wss")
            pair = acceptance.build_config_pair(case, material, 10001, 10002, 10003, 10004)
            self.assertTrue(pair.requires_tls_forwarder)
            self.assertEqual("none", pair.server["inbounds"][0]["streamSettings"]["security"])
            self.assertEqual("tls", pair.client["outbounds"][0]["streamSettings"]["security"])

    def test_hysteria2_matches_xray_26327_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            material = make_material(Path(temporary))
            case = next(item for item in acceptance.XRAY_CASES if item.case_id == "hysteria2")
            pair = acceptance.build_config_pair(case, material, 10001, 10001, 10003, 10004)
            inbound = pair.server["inbounds"][0]
            outbound = pair.client["outbounds"][0]
            self.assertEqual("hysteria", inbound["protocol"])
            self.assertIn("clients", inbound["settings"])
            self.assertNotIn("users", inbound["settings"])
            self.assertEqual({"version": 2}, inbound["streamSettings"]["hysteriaSettings"])
            self.assertEqual(["h3"], inbound["streamSettings"]["tlsSettings"]["alpn"])
            self.assertEqual(
                {"version": 2, "auth": material.credentials.password},
                outbound["streamSettings"]["hysteriaSettings"],
            )
            self.assertNotIn("password", inbound["streamSettings"]["hysteriaSettings"])

    def test_wireguard_pair_uses_userspace_client(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            material = make_material(Path(temporary))
            pair = acceptance.build_wireguard_pair(material, 10001, 10002, 10003)
            server_settings = pair.server["inbounds"][0]["settings"]
            client_settings = pair.client["outbounds"][0]["settings"]
            self.assertFalse(server_settings["noKernelTun"])
            self.assertTrue(client_settings["noKernelTun"])
            self.assertEqual(["10.66.66.2/32"], server_settings["peers"][0]["allowedIPs"])
            self.assertEqual(["0.0.0.0/0"], client_settings["peers"][0]["allowedIPs"])
            self.assertEqual("127.0.0.1:10001", client_settings["peers"][0]["endpoint"])
            self.assertEqual(
                "127.0.0.1:10003",
                pair.server["outbounds"][0]["settings"]["redirect"],
            )

    def test_anydoor_config_forwards_tcp_and_udp(self) -> None:
        config = acceptance.build_anydoor_config(
            "acceptance-anydoor-c",
            "127.0.0.12",
            2033,
            "127.0.0.1",
            8080,
            send_through=acceptance.EXPECTED_EXIT_IP,
        )
        inbound = config["inbounds"][0]
        self.assertEqual("tunnel", inbound["protocol"])
        self.assertEqual("tcp,udp", inbound["settings"]["network"])
        self.assertEqual(2033, inbound["port"])
        self.assertEqual(acceptance.EXPECTED_EXIT_IP, config["outbounds"][0]["sendThrough"])

    def test_probe_server_echoes_udp_nonce(self) -> None:
        probe = acceptance.ProbeServer()
        probe.start()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(2)
                client.sendto(b"unit-test-token", (acceptance.LOOPBACK, probe.port))
                payload, _ = client.recvfrom(4096)
            response = json.loads(payload)
            self.assertEqual("unit-test-token", response["token"])
            self.assertEqual(acceptance.LOOPBACK, response["remote_ip"])
        finally:
            probe.close()

    def test_secure_json_permissions_and_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.json"
            acceptance.secure_write_json(path, {"password": "sensitive-password-value"})
            self.assertEqual(stat.S_IRUSR | stat.S_IWUSR, stat.S_IMODE(path.stat().st_mode))
            redacted = acceptance.redact(
                "password=sensitive-password-value publicKey=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123456789+/=",
                ["sensitive-password-value"],
            )
            self.assertNotIn("sensitive-password-value", redacted)
            self.assertNotIn("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123456789+/=", redacted)


if __name__ == "__main__":
    unittest.main()
