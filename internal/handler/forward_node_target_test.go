package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/storage"
)

func TestForwardNodeRetarget(t *testing.T) {
	for _, scenario := range []string{"success", "domain", "stored-domain", "server-ip", "replace-domain", "stale-server-domain", "domain-rejected", "bad-domain", "stale-domain", "rejected", "wrong-ack", "self", "stale", "non-admin", "arbitrary-address"} {
		t.Run(scenario, func(t *testing.T) {
			ctx := context.Background()
			repo := newRemoteHandlerTestRepo(t)
			if err := repo.CreateUser(ctx, "admin", "", "", "hash", storage.RoleAdmin, ""); err != nil {
				t.Fatal(err)
			}
			var applied []map[string]interface{}
			agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/api/child/inbounds" {
					http.NotFound(w, r)
					return
				}
				var req map[string]interface{}
				_ = json.NewDecoder(r.Body).Decode(&req)
				in, _ := req["inbound"].(map[string]interface{})
				applied = append(applied, in)
				response := map[string]interface{}{"success": true, "mutation_id": req["mutation_id"]}
				if len(applied) == 1 && (scenario == "rejected" || scenario == "domain-rejected") {
					response["success"] = false
				}
				if len(applied) == 1 && scenario == "wrong-ack" {
					response["mutation_id"] = "another-owner"
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer agent.Close()
			server := createRemoteHandlerTestServer(t, repo, "entry", agent.URL)
			create := func(name, host, proto string, forward bool) storage.Node {
				cfg := map[string]interface{}{"name": name, "server": host, "port": 443, "type": proto, "password": "credential-" + name}
				b, _ := json.Marshal(cfg)
				n, err := repo.CreateNode(ctx, storage.Node{Username: "admin", NodeName: name, Protocol: proto, ParsedConfig: string(b), ClashConfig: string(b), Enabled: true, OriginalServer: server.Name, InboundTag: name})
				if err != nil {
					t.Fatal(err)
				}
				if forward {
					if err := repo.MarkNodeForwarded(ctx, n.ID); err != nil {
						t.Fatal(err)
					}
					n.NodeType = "forwarded"
				}
				return n
			}
			old := create("old", "old.example.test", "ss", false)
			target := create("new", "new.example.test", "trojan", false)
			entry := create("entry", "entry.example.test", "ss", true)
			var cfg map[string]interface{}
			_ = json.Unmarshal([]byte(entry.ClashConfig), &cfg)
			cfg["password"] = "credential-old"
			b, _ := json.Marshal(cfg)
			entry.ClashConfig = string(b)
			entry.ParsedConfig = string(b)
			var err error
			entry, err = repo.UpdateNode(ctx, entry)
			if err != nil {
				t.Fatal(err)
			}
			in := map[string]interface{}{"tag": "entry", "protocol": "tunnel", "port": 443, "settings": map[string]interface{}{"address": "old.example.test", "port": 443, "network": "tcp,udp"}}
			inJSON, _ := json.Marshal(in)
			if _, err := repo.UpsertActiveDesiredInbound(ctx, server.ID, "entry", "owner", inJSON); err != nil {
				t.Fatal(err)
			}
			if err := repo.SetRemoteInboundOwnership(ctx, server.ID, "entry", "owner"); err != nil {
				t.Fatal(err)
			}
			targetID := target.ID
			expected := old.ID
			username := "admin"
			if scenario == "self" {
				targetID = entry.ID
			}
			if scenario == "stale" {
				expected = 999
			}
			if scenario == "non-admin" {
				username = "unknown"
			}
			body := map[string]interface{}{"target_node_id": targetID, "expected_target_node_id": expected, "node_name": "custom entry", "enabled": true, "tags": []string{"HK"}}
			if scenario == "arbitrary-address" {
				body["server"] = "attacker.example.test"
			}
			if scenario == "domain" || scenario == "domain-rejected" {
				body["target_host"] = "DYNAMIC.example.test."
				body["expected_target_host"] = ""
			}
			if scenario == "bad-domain" {
				body["target_host"] = "https://dynamic.example.test:443/path"
			}
			if scenario == "stale-domain" {
				body["expected_target_host"] = "stale.example.test"
			}
			initialDomain := ""
			if scenario == "stored-domain" || scenario == "replace-domain" || scenario == "stale-server-domain" || scenario == "server-ip" {
				initialDomain = "stored.example.test"
				if err := repo.UpdateRemoteServerDomain(ctx, server.ID, initialDomain); err != nil {
					t.Fatal(err)
				}
				body["use_server_domain"] = scenario != "server-ip"
				body["expected_server_domain"] = initialDomain
			}
			if scenario == "replace-domain" {
				body["target_host"] = "other.example.test"
			}
			if scenario == "stale-server-domain" {
				body["expected_server_domain"] = "stale.example.test"
			}
			raw, _ := json.Marshal(body)
			request := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/admin/forward-nodes/%d/target", entry.ID), bytes.NewReader(raw))
			request = request.WithContext(auth.ContextWithUsername(ctx, username))
			response := httptest.NewRecorder()
			NewRemoteManageHandler(repo, nil).HandleForwardNodeTarget(response, request)
			links, err := repo.ForwardNodeTargets(ctx)
			if err != nil {
				t.Fatal(err)
			}
			got, err := repo.GetNodeByID(ctx, entry.ID)
			if err != nil {
				t.Fatal(err)
			}
			desired, err := repo.GetDesiredInbound(ctx, server.ID, "entry")
			if err != nil {
				t.Fatal(err)
			}
			var want map[string]interface{}
			_ = json.Unmarshal(desired.InboundJSON, &want)
			if scenario == "success" || scenario == "domain" || scenario == "stored-domain" || scenario == "server-ip" {
				if response.Code != 200 || links[entry.ID] != target.ID || got.Protocol != "trojan" || got.NodeName != "custom entry" || len(applied) != 1 {
					t.Fatalf("retarget failed code=%d binding=%d calls=%d response=%s", response.Code, links[entry.ID], len(applied), response.Body.String())
				}
				var client map[string]interface{}
				_ = json.Unmarshal([]byte(got.ClashConfig), &client)
				expectedHost := "new.example.test"
				if scenario == "domain" {
					expectedHost = "dynamic.example.test"
				}
				if scenario == "stored-domain" {
					expectedHost = initialDomain
				}
				if scenario == "server-ip" {
					expectedHost = "127.0.0.1"
				}
				if client["server"] != "entry.example.test" || client["password"] != "credential-new" || client["type"] != "trojan" || want["settings"].(map[string]interface{})["address"] != expectedHost || applied[0]["settings"].(map[string]interface{})["address"] != expectedHost {
					t.Fatal("runtime and subscription did not switch together")
				}
				// Explicit identity still wins when an equivalent source is later added.
				create("alias", "new.example.test", "trojan", false)
				links, _ = repo.ForwardNodeTargets(ctx)
				if links[entry.ID] != target.ID {
					t.Fatal("explicit binding lost")
				}
				if scenario == "domain" {
					hosts, _ := repo.ForwardNodeTargetHosts(ctx)
					if hosts[entry.ID] != "dynamic.example.test" {
						t.Fatal("DNS override lost")
					}
					synced, _ := repo.GetRemoteServer(ctx, server.ID)
					if synced.Domain != "dynamic.example.test" {
						t.Fatal("new domain not synchronized to server management")
					}
					view := convertAdminNodes(ctx, repo, []storage.Node{got})
					if view[0].ForwardTargetHost != "dynamic.example.test" || view[0].ForwardNodeID == nil || *view[0].ForwardNodeID != target.ID {
						t.Fatal("admin view lost DDNS or node binding")
					}
					// Saving metadata through an older client must preserve DDNS.
					delete(body, "target_host")
					delete(body, "expected_target_host")
					body["expected_target_node_id"] = target.ID
					raw, _ = json.Marshal(body)
					request = httptest.NewRequest(http.MethodPost, request.URL.Path, bytes.NewReader(raw)).WithContext(auth.ContextWithUsername(ctx, "admin"))
					response = httptest.NewRecorder()
					NewRemoteManageHandler(repo, nil).HandleForwardNodeTarget(response, request)
					if response.Code != 200 || applied[len(applied)-1]["settings"].(map[string]interface{})["address"] != "dynamic.example.test" {
						t.Fatal("legacy metadata save erased domain")
					}
					body["target_host"] = ""
					body["expected_target_host"] = "dynamic.example.test"
					raw, _ = json.Marshal(body)
					request = httptest.NewRequest(http.MethodPost, request.URL.Path, bytes.NewReader(raw)).WithContext(auth.ContextWithUsername(ctx, "admin"))
					response = httptest.NewRecorder()
					NewRemoteManageHandler(repo, nil).HandleForwardNodeTarget(response, request)
					if response.Code != 200 || applied[len(applied)-1]["settings"].(map[string]interface{})["address"] != "new.example.test" {
						t.Fatal("follow-node mode did not clear override")
					}
				}
			} else {
				restored, _ := repo.GetRemoteServer(ctx, server.ID)
				if restored.Domain != initialDomain {
					t.Fatal("failed forwarding change modified server domain")
				}
				if response.Code == 200 || links[entry.ID] != old.ID || got.ClashConfig != entry.ClashConfig || want["settings"].(map[string]interface{})["address"] != "old.example.test" {
					t.Fatalf("unsafe failed mutation code=%d binding=%d response=%s", response.Code, links[entry.ID], response.Body.String())
				}
				calls := 0
				if scenario == "rejected" || scenario == "wrong-ack" || scenario == "domain-rejected" {
					calls = 2
				}
				if len(applied) != calls {
					t.Fatalf("Agent calls=%d want %d", len(applied), calls)
				}
			}
		})
	}
}

func TestForwardTargetDomainValidation(t *testing.T) {
	for _, raw := range []string{"192.0.2.10", "127.0.0.1", "https://ddns.example.test", "ddns.example.test:443", "*.example.test", "-bad.example.test", "bad..example.test", "bad.example.test/path"} {
		if _, err := normalizeForwardTargetDomain(raw); err == nil {
			t.Errorf("accepted invalid domain %q", raw)
		}
	}
	got, err := normalizeForwardTargetDomain(" DDNS.example.test. ")
	if err != nil || got != "ddns.example.test" {
		t.Fatal("valid DDNS domain rejected")
	}
}
