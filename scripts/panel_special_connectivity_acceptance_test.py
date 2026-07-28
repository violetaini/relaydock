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
                for resource in [item for item in self.resources if item["inbound_tag"] == tag]:
                    server_id = int(resource["server_id"])
                    self.inbounds[server_id] = [
                        item for item in self.inbounds.get(server_id, []) if item.get("tag") != tag
                    ]
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


class PanelSpecialAcceptanceTest(unittest.TestCase):
    def test_chain_label_is_valid_for_long_run_id(self) -> None:
        label = special.chain_label("a" * 40)
        self.assertRegex(label, r"^[a-z0-9-]{2,32}$")
        self.assertLessEqual(len(label), 32)

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

    def test_chain_request_uses_same_port_everywhere(self) -> None:
        request = special.build_chain_request("accept-unit01-abcd1234", [1, 2], 2033, "192.0.2.10")
        self.assertEqual(2033, request["entry_port"])
        self.assertEqual(2033, request["target_port"])
        self.assertEqual([1, 2], request["server_ids"])

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

    def test_chain_cleanup_is_reverse_order_and_exact(self) -> None:
        api = CleanupAPI()
        label = "accept-unit01-abcd1234"
        api.inbounds = {
            1: [{"tag": special.chain_tag(label, 0)}],
            2: [{"tag": special.chain_tag(label, 1)}],
        }
        special.cleanup_chain(api, [1, 2], label)
        removals = [request for request in api.requests if request[0] == "POST"]
        self.assertEqual(2, len(removals))
        self.assertIn("server_id=2", removals[0][1])
        assert isinstance(removals[0][2], dict)
        self.assertEqual(special.chain_tag(label, 1), removals[0][2]["tag"])
        self.assertIn("server_id=1", removals[1][1])

    def test_chain_cleanup_refuses_unowned_label_without_requests(self) -> None:
        api = CleanupAPI()
        with self.assertRaises(special.PanelAcceptanceError):
            special.cleanup_chain(api, [1, 2], "production")
        self.assertEqual([], api.requests)

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
            "--chain-server-id", "1",
            "--chain-server-id", "2",
            "--target-host", "192.0.2.10",
        ])
        with self.assertRaises(special.PanelAcceptanceError):
            special.validate_args(args, ["anydoor"])


if __name__ == "__main__":
    unittest.main()
