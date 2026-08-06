from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


SCRIPT_PATH = Path(__file__).with_name("panel_special_connectivity_acceptance.py")
SPEC = importlib.util.spec_from_file_location("panel_special_connectivity_acceptance", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
special = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = special
SPEC.loader.exec_module(special)


class CleanupAPI:
    def __init__(self) -> None:
        self.inbounds: dict[int, list[dict[str, object]]] = {}
        self.resources: list[dict[str, object]] = []
        self.nodes: list[dict[str, object]] = []
        self.requests: list[tuple[str, str, object | None]] = []

    def request(self, method: str, path: str, body: object | None = None) -> object:
        self.requests.append((method, path, body))
        if method == "GET" and path == "/api/admin/managed-inbound-resources":
            return {"success": True, "resources": list(self.resources)}
        if method == "GET" and path == "/api/admin/nodes?include_private=1":
            return {"success": True, "nodes": list(self.nodes)}
        if method == "GET" and path.startswith("/api/admin/nodes/") and path.endswith("/uri"):
            node_id = int(path.split("/")[-2])
            matching = [item for item in self.nodes if item["id"] == node_id]
            if not matching:
                return {"success": False}
            return {"item": {"uri": "wireguard://unit-test"}}
        if method == "DELETE" and path.startswith("/api/admin/nodes/"):
            node_id = int(path.rsplit("/", 1)[1])
            matching = [item for item in self.nodes if item["id"] == node_id]
            self.nodes = [item for item in self.nodes if item["id"] != node_id]
            for node in matching:
                tag = str(node["inbound_tag"])
                for server_id in list(self.inbounds):
                    self.inbounds[server_id] = [
                        item for item in self.inbounds.get(server_id, []) if item.get("tag") != tag
                    ]
                for resource in [item for item in self.resources if item["inbound_tag"] == tag]:
                    server_id = int(resource["server_id"])
                    self.inbounds.setdefault(server_id, [])
                self.resources = [item for item in self.resources if item["inbound_tag"] != tag]
            return {"status": "deleted"}
        if method == "DELETE" and path.startswith("/api/admin/managed-inbound-resources/"):
            resource_id = int(path.rsplit("/", 1)[1])
            matching = [item for item in self.resources if item["id"] == resource_id]
            self.resources = [item for item in self.resources if item["id"] != resource_id]
            for resource in matching:
                server_id = int(resource["server_id"])
                tag = str(resource["inbound_tag"])
                self.inbounds[server_id] = [item for item in self.inbounds.get(server_id, []) if item.get("tag") != tag]
            return {"success": True}
        if method == "GET" and path.startswith("/api/admin/remote/inbounds?server_id="):
            server_id = int(path.rsplit("=", 1)[1])
            return {"success": True, "inbounds": list(self.inbounds.get(server_id, []))}
        if method == "POST" and path.startswith("/api/admin/remote/inbounds?server_id="):
            server_id = int(path.rsplit("=", 1)[1])
            assert isinstance(body, dict)
            tag = str(body["tag"])
            self.inbounds[server_id] = [item for item in self.inbounds.get(server_id, []) if item.get("tag") != tag]
            return {"success": True}
        raise AssertionError((method, path, body))


class BrokenNodeCleanupAPI(CleanupAPI):
    def request(self, method: str, path: str, body: object | None = None) -> object:
        if method == "DELETE" and path.startswith("/api/admin/nodes/"):
            self.requests.append((method, path, body))
            node_id = int(path.rsplit("/", 1)[1])
            self.nodes = [item for item in self.nodes if item["id"] != node_id]
            return {"status": "deleted"}
        return super().request(method, path, body)


class AnyDoorRunAPI(CleanupAPI):
    def request(self, method: str, path: str, body: object | None = None) -> object:
        if method == "POST" and path.startswith("/api/admin/managed-nodes/create?server_id="):
            self.requests.append((method, path, body))
            server_id = int(path.rsplit("=", 1)[1])
            assert isinstance(body, dict) and isinstance(body.get("inbound"), dict)
            inbound = dict(body["inbound"])
            tag = str(inbound["tag"])
            node = {
                "id": 21,
                "inbound_tag": tag,
                "protocol": "vless",
                "clash_config": {
                    "type": "vless",
                    "server": "entry.example.test",
                    "port": inbound["port"],
                },
            }
            self.nodes = [node]
            self.inbounds[server_id] = [inbound]
            return {"success": True, "node_id": 21, "node": node}
        return super().request(method, path, body)


class PanelSpecialAcceptanceTest(unittest.TestCase):
    def test_anydoor_tag_uses_the_run_owned_namespace(self) -> None:
        self.assertEqual("accept-unit01-anydoor", special.anydoor_tag("unit01"))

    def test_wireguard_request_separates_client_private_key_from_agent_inbound(self) -> None:
        client_private = "C" * 43 + "="
        request = special.build_wireguard_request(
            "accept-unit01-wireguard", 51920,
            "S" * 43 + "=", "R" * 43 + "=", client_private, "P" * 43 + "=",
            "10.220.1.1/32", "10.220.1.2/32", "1.1.1.1",
        )
        inbound = request["inbound"]
        assert isinstance(inbound, dict)
        self.assertIn("secretKey", str(inbound))
        self.assertNotIn(client_private, str(inbound))
        settings = inbound["settings"]
        assert isinstance(settings, dict)
        peers = settings["peers"]
        assert isinstance(peers, list) and isinstance(peers[0], dict)
        self.assertEqual("P" * 43 + "=", peers[0]["publicKey"])
        client = request["client"]
        assert isinstance(client, dict)
        self.assertEqual(client_private, client["private_key"])
        self.assertEqual("R" * 43 + "=", client["server_public_key"])
        self.assertEqual(["10.220.1.2/32"], client["address"])
        self.assertEqual(["1.1.1.1"], client["dns"])
        self.assertEqual(["0.0.0.0/0"], client["allowed_ips"])

    def test_wireguard_client_uses_only_client_private_and_server_public(self) -> None:
        config = special.build_wireguard_client(
            "2001:db8::1", 51920, "C" * 43 + "=", "S" * 43 + "=",
            "10.220.1.2/32", 39001, 39002, "1.1.1.1",
        )
        outbounds = config["outbounds"]
        assert isinstance(outbounds, list) and isinstance(outbounds[0], dict)
        settings = outbounds[0]["settings"]
        assert isinstance(settings, dict)
        peers = settings["peers"]
        assert isinstance(peers, list) and isinstance(peers[0], dict)
        self.assertEqual("C" * 43 + "=", settings["secretKey"])
        self.assertEqual("S" * 43 + "=", peers[0]["publicKey"])
        self.assertEqual("[2001:db8::1]:51920", peers[0]["endpoint"])
        inbounds = config["inbounds"]
        assert isinstance(inbounds, list) and isinstance(inbounds[1], dict)
        udp_settings = inbounds[1]["settings"]
        assert isinstance(udp_settings, dict)
        self.assertEqual("udp", udp_settings["network"])

    def test_anydoor_request_uses_the_managed_node_transaction(self) -> None:
        request = special.build_anydoor_request(
            "accept-unit01-anydoor", 17, 2033, "192.0.2.10", 2044,
        )
        self.assertEqual("add", request["action"])
        self.assertEqual(17, request["forward_node_id"])
        inbound = request["inbound"]
        assert isinstance(inbound, dict)
        self.assertEqual("accept-unit01-anydoor", inbound["tag"])
        self.assertEqual("tunnel", inbound["protocol"])
        self.assertEqual(2033, inbound["port"])
        self.assertEqual(
            {"address": "192.0.2.10", "port": 2044, "network": "tcp,udp"},
            inbound["settings"],
        )

    def test_wireguard_response_requires_normal_node_and_subscription_share(self) -> None:
        api = CleanupAPI()
        tag = "accept-unit01-wireguard"
        client_private = "C" * 43 + "="
        server_public = "S" * 43 + "="
        clash = {
            "name": "Acceptance WireGuard",
            "type": "wireguard",
            "server": "2001:db8::1",
            "port": 51920,
            "private-key": client_private,
            "public-key": server_public,
        }
        node = {
            "id": 11,
            "inbound_tag": tag,
            "protocol": "wireguard",
            "clash_config": clash,
        }
        resource = {
            "id": 7,
            "server_id": 1,
            "inbound_tag": tag,
            "protocol": "wireguard",
            "endpoint_host": "2001:db8::1",
            "endpoint_port": 51920,
            "public_metadata": {"server_public_key": server_public},
        }
        api.nodes = [node]
        api.resources = [resource]
        api.inbounds[1] = [{"tag": tag, "protocol": "wireguard", "port": 51920}]
        response = {
            "success": True,
            "resource": resource,
            "node": node,
            "node_id": 11,
            "client_config": (
                "[Interface]\n"
                f"PrivateKey = {client_private}\n\n"
                "[Peer]\n"
                f"PublicKey = {server_public}\n"
                "Endpoint = [2001:db8::1]:51920\n"
            ),
        }
        result = special.validate_wireguard_response(
            api, response, 1, tag, 51920, server_public, client_private,
        )
        self.assertEqual((7, 11, "2001:db8::1", clash), result)
        self.assertIn(("GET", "/api/admin/nodes/11/uri", None), api.requests)

    def test_wireguard_response_rejects_client_private_key_in_agent_readback(self) -> None:
        api = CleanupAPI()
        tag = "accept-unit01-wireguard"
        client_private = "C" * 43 + "="
        server_public = "S" * 43 + "="
        resource = {
            "id": 7,
            "server_id": 1,
            "inbound_tag": tag,
            "protocol": "wireguard",
            "endpoint_host": "192.0.2.1",
            "endpoint_port": 51920,
            "public_metadata": {"server_public_key": server_public},
        }
        api.inbounds[1] = [{
            "tag": tag,
            "protocol": "wireguard",
            "port": 51920,
            "settings": {"client_private_key": client_private},
        }]
        with self.assertRaisesRegex(special.PanelAcceptanceError, "leaked into the Agent"):
            special.validate_wireguard_response(
                api, {"success": True, "resource": resource},
                1, tag, 51920, server_public, client_private,
            )

    def test_wireguard_cleanup_prefers_normal_node_and_verifies_absence(self) -> None:
        api = CleanupAPI()
        tag = "accept-unit01-wireguard"
        api.inbounds[1] = [{"tag": tag, "protocol": "wireguard", "port": 51920}]
        api.resources = [{"id": 7, "server_id": 1, "inbound_tag": tag}]
        api.nodes = [{"id": 11, "inbound_tag": tag, "protocol": "wireguard"}]
        special.cleanup_wireguard(api, 1, tag, tag)
        self.assertIn(("DELETE", "/api/admin/nodes/11", None), api.requests)
        self.assertNotIn(("DELETE", "/api/admin/managed-inbound-resources/7", None), api.requests)
        self.assertEqual([], api.inbounds[1])
        self.assertEqual([], api.resources)
        self.assertEqual([], api.nodes)

    def test_wireguard_cleanup_uses_compatibility_resource_for_half_create(self) -> None:
        api = CleanupAPI()
        tag = "accept-unit01-wireguard"
        api.inbounds[1] = [{"tag": tag, "protocol": "wireguard", "port": 51920}]
        api.resources = [{"id": 7, "server_id": 1, "inbound_tag": tag}]
        special.cleanup_wireguard(api, 1, tag, tag)
        self.assertIn(("DELETE", "/api/admin/managed-inbound-resources/7", None), api.requests)
        self.assertEqual([], api.inbounds[1])
        self.assertEqual([], api.resources)

    def test_wireguard_cleanup_reports_broken_normal_node_lifecycle_after_fallback(self) -> None:
        api = BrokenNodeCleanupAPI()
        tag = "accept-unit01-wireguard"
        api.inbounds[1] = [{"tag": tag, "protocol": "wireguard", "port": 51920}]
        api.resources = [{"id": 7, "server_id": 1, "inbound_tag": tag}]
        api.nodes = [{"id": 11, "inbound_tag": tag, "protocol": "wireguard"}]
        with self.assertRaisesRegex(special.PanelAcceptanceError, "normal WireGuard node deletion"):
            special.cleanup_wireguard(api, 1, tag, tag)
        self.assertEqual([], api.nodes)
        self.assertEqual([], api.resources)
        self.assertEqual([], api.inbounds[1])

    def test_wireguard_cleanup_refuses_unowned_tag_without_requests(self) -> None:
        api = CleanupAPI()
        with self.assertRaises(special.PanelAcceptanceError):
            special.cleanup_wireguard(api, 1, "production-wireguard", "accept-unit01-wireguard")
        self.assertEqual([], api.requests)

    def test_anydoor_response_requires_normal_clone_and_agent_readback(self) -> None:
        api = CleanupAPI()
        tag = "accept-unit01-anydoor"
        node = {
            "id": 21,
            "inbound_tag": tag,
            "protocol": "vless",
            "clash_config": {"type": "vless", "server": "entry.example.test", "port": 2033},
        }
        api.nodes = [node]
        api.inbounds[3] = [{
            "tag": tag,
            "protocol": "tunnel",
            "port": 2033,
            "settings": {"address": "192.0.2.10", "port": 2044, "network": "tcp,udp"},
        }]
        result = special.validate_anydoor_response(
            api, {"success": True, "node_id": 21, "node": node},
            3, tag, 2033, "192.0.2.10", 2044,
        )
        self.assertEqual((21, "entry.example.test"), result)

    def test_anydoor_cleanup_uses_the_normal_node_lifecycle(self) -> None:
        api = CleanupAPI()
        tag = "accept-unit01-anydoor"
        api.nodes = [{"id": 21, "inbound_tag": tag, "protocol": "vless"}]
        api.inbounds[3] = [{"tag": tag, "protocol": "tunnel", "port": 2033}]
        special.cleanup_anydoor(api, 3, tag, tag, 21)
        self.assertIn(("DELETE", "/api/admin/nodes/21", None), api.requests)
        self.assertFalse(any(request[0] == "POST" for request in api.requests))
        self.assertEqual([], api.nodes)
        self.assertEqual([], api.inbounds[3])

    def test_anydoor_cleanup_reports_a_broken_node_lifecycle_after_fallback(self) -> None:
        api = BrokenNodeCleanupAPI()
        tag = "accept-unit01-anydoor"
        api.nodes = [{"id": 21, "inbound_tag": tag, "protocol": "vless"}]
        api.inbounds[3] = [{"tag": tag, "protocol": "tunnel", "port": 2033}]
        with self.assertRaisesRegex(special.PanelAcceptanceError, "normal AnyDoor node deletion"):
            special.cleanup_anydoor(api, 3, tag, tag, 21)
        self.assertEqual([], api.nodes)
        self.assertEqual([], api.inbounds[3])

    def test_anydoor_cleanup_refuses_unowned_tag_without_requests(self) -> None:
        api = CleanupAPI()
        with self.assertRaises(special.PanelAcceptanceError):
            special.cleanup_anydoor(api, 3, "production-anydoor", "accept-unit01-anydoor")
        self.assertEqual([], api.requests)

    def test_anydoor_run_uses_current_managed_node_endpoint_and_cleans_up(self) -> None:
        api = AnyDoorRunAPI()
        args = special.parser().parse_args([
            "--base-url", "https://panel.example",
            "--case", "anydoor",
            "--anydoor-server-id", "3",
            "--anydoor-forward-node-id", "17",
            "--anydoor-port", "2033",
            "--target-host", "192.0.2.10",
            "--target-port", "2044",
        ])
        original_tcp, original_udp = special.probe_tcp_echo, special.probe_udp_echo
        special.probe_tcp_echo = lambda *_args: None
        special.probe_udp_echo = lambda *_args: None
        try:
            special.run_anydoor(args, api, "unit01")
        finally:
            special.probe_tcp_echo, special.probe_udp_echo = original_tcp, original_udp
        creates = [request for request in api.requests if request[0] == "POST" and "managed-nodes/create" in request[1]]
        self.assertEqual(1, len(creates))
        self.assertEqual("/api/admin/managed-nodes/create?server_id=3", creates[0][1])
        self.assertEqual([], api.nodes)
        self.assertEqual([], api.inbounds[3])

    def test_echo_probe_handles_tcp_and_udp(self) -> None:
        echo = special.EchoProbe("127.0.0.1", 0)
        echo.start()
        try:
            special.probe_tcp_echo("127.0.0.1", echo.port, 2)
            special.probe_udp_echo("127.0.0.1", echo.port, 2)
        finally:
            echo.close()

    def test_dns_query_has_standard_question(self) -> None:
        transaction_id, query = special.dns_query("example.com")
        self.assertEqual(transaction_id, int.from_bytes(query[:2], "big"))
        self.assertIn(b"\x07example\x03com\x00", query)

    def test_dry_run_needs_no_token_or_api(self) -> None:
        code = special.main([
            "--base-url", "https://panel.example",
            "--case", "wireguard",
            "--run-id", "unit01",
        ])
        self.assertEqual(0, code)

    def test_external_echo_requires_explicit_port(self) -> None:
        args = special.parser().parse_args([
            "--base-url", "https://panel.example",
            "--case", "anydoor",
            "--anydoor-server-id", "1",
            "--anydoor-forward-node-id", "17",
            "--target-host", "192.0.2.10",
        ])
        with self.assertRaises(special.PanelAcceptanceError):
            special.validate_args(args, ["anydoor"])


if __name__ == "__main__":
    unittest.main()
