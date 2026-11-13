package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func TestIsPackageNodeMultiUserEligible(t *testing.T) {
	tests := []struct {
		name     string
		node     storage.Node
		expected bool
	}{
		{
			name: "anydoor tunnel node by tag",
			node: storage.Node{
				NodeName:   "Tunnel 1",
				Protocol:   "tunnel",
				InboundTag: "anydoor-12345",
			},
			expected: false,
		},
		{
			name: "dokodemo-door forward node",
			node: storage.Node{
				NodeName:   "Forward 1",
				Protocol:   "dokodemo-door",
				InboundTag: "inbound-2133",
			},
			expected: false,
		},
		{
			name: "shadowsocks chacha20 single-password",
			node: storage.Node{
				NodeName:    "SS ChaCha20",
				Protocol:    "ss",
				InboundTag:  "inbound-ss-1",
				ClashConfig: `{"name":"SS ChaCha20","type":"ss","server":"1.2.3.4","port":1001,"cipher":"chacha20-ietf-poly1305","password":"test"}`,
			},
			expected: false,
		},
		{
			name: "shadowsocks classic aes without multi-user marker",
			node: storage.Node{
				NodeName:    "SS Classic Single",
				Protocol:    "shadowsocks",
				InboundTag:  "inbound-ss-2",
				ClashConfig: `{"name":"SS Single","type":"ss","server":"1.2.3.4","port":1002,"cipher":"aes-128-gcm","password":"test"}`,
			},
			expected: false,
		},
		{
			name: "shadowsocks classic aes with multi-user marker",
			node: storage.Node{
				NodeName:    "SS Classic MultiUser",
				Protocol:    "shadowsocks",
				InboundTag:  "inbound-ss-3",
				ClashConfig: `{"name":"SS Multi","type":"ss","server":"1.2.3.4","port":1003,"cipher":"aes-128-gcm","password":"test","x-arcway-managed-users":true}`,
			},
			expected: true,
		},
		{
			name: "shadowsocks 2022",
			node: storage.Node{
				NodeName:    "SS 2022",
				Protocol:    "ss",
				InboundTag:  "inbound-ss-4",
				ClashConfig: `{"name":"SS 2022","type":"ss","server":"1.2.3.4","port":1004,"cipher":"2022-blake3-aes-128-gcm","password":"master:user"}`,
			},
			expected: true,
		},
		{
			name: "vless multi-user",
			node: storage.Node{
				NodeName:   "VLESS 1",
				Protocol:   "vless",
				InboundTag: "inbound-vl",
			},
			expected: true,
		},
		{
			name: "trojan multi-user",
			node: storage.Node{
				NodeName:   "Trojan 1",
				Protocol:   "trojan",
				InboundTag: "inbound-tr",
			},
			expected: true,
		},
		{
			name: "hysteria2 multi-user",
			node: storage.Node{
				NodeName:   "HY2 1",
				Protocol:   "hysteria2",
				InboundTag: "inbound-hy2",
			},
			expected: true,
		},
		{
			name: "chitanda protocol",
			node: storage.Node{
				NodeName:   "Chitanda 1",
				Protocol:   "chitanda",
				InboundTag: "inbound-ch",
			},
			expected: true,
		},
		{
			name: "unmanaged static wireguard",
			node: storage.Node{
				NodeName:       "WG Static",
				Protocol:       "wireguard",
				OriginalServer: "",
				InboundTag:     "",
			},
			expected: false,
		},
		{
			name: "managed wireguard",
			node: storage.Node{
				NodeName:       "WG Managed",
				Protocol:       "wireguard",
				OriginalServer: "server-1",
				InboundTag:     "wg-in",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eligible, reason := isPackageNodeMultiUserEligible(tt.node)
			if eligible != tt.expected {
				t.Fatalf("isPackageNodeMultiUserEligible() = %v (reason=%q), want %v", eligible, reason, tt.expected)
			}
		})
	}
}

func TestPackageCreateAndValidationRejectsNonMultiUserNodes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "package-node-eligibility.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	tunnelNode, err := repo.CreateNode(ctx, storage.Node{
		Username:    "admin",
		NodeName:    "AnyDoor Forward 01",
		Protocol:    "dokodemo-door",
		InboundTag:  "anydoor-9999",
		ClashConfig: `{"name":"Tunnel","type":"tunnel","server":"1.2.3.4","port":9999}`,
	})
	if err != nil {
		t.Fatal(err)
	}

	chachaNode, err := repo.CreateNode(ctx, storage.Node{
		Username:    "admin",
		NodeName:    "SS ChaCha20 Shared",
		Protocol:    "ss",
		InboundTag:  "inbound-8888",
		ClashConfig: `{"name":"SS","type":"ss","server":"1.2.3.4","port":8888,"cipher":"chacha20-ietf-poly1305","password":"test"}`,
	})
	if err != nil {
		t.Fatal(err)
	}

	validNode, err := repo.CreateNode(ctx, storage.Node{
		Username:    "admin",
		NodeName:    "VLESS Global",
		Protocol:    "vless",
		InboundTag:  "inbound-7777",
		ClashConfig: `{"name":"VLESS","type":"vless","server":"1.2.3.4","port":7777,"uuid":"00000000-0000-0000-0000-000000000000"}`,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1) Test validatePackageNodeMultiUserSupport directly
	if err := validatePackageNodeMultiUserSupport(ctx, repo, []int64{tunnelNode.ID}); err == nil {
		t.Fatal("expected error validating tunnel node in package, got nil")
	}
	if err := validatePackageNodeMultiUserSupport(ctx, repo, []int64{chachaNode.ID}); err == nil {
		t.Fatal("expected error validating chacha20 node in package, got nil")
	}
	if err := validatePackageNodeMultiUserSupport(ctx, repo, []int64{validNode.ID}); err != nil {
		t.Fatalf("unexpected error validating valid node in package: %v", err)
	}

	// 2) Test PackageCreateHandler rejects ineligible node
	createHandler := NewPackageCreateHandler(repo)
	ineligiblePayload, _ := json.Marshal(map[string]any{
		"name":       "Test Bad Package",
		"cycle_days": 30,
		"nodes":      []int64{chachaNode.ID},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/admin/packages/create", bytes.NewReader(ineligiblePayload))
	rec := httptest.NewRecorder()
	createHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected HTTP 400 when creating package with chacha20 node, got %d: %s", rec.Code, rec.Body.String())
	}

	// 3) Test PackageCreateHandler accepts valid multi-user node
	validPayload, _ := json.Marshal(map[string]any{
		"name":       "Test Good Package",
		"cycle_days": 30,
		"nodes":      []int64{validNode.ID},
	})
	reqValid := httptest.NewRequest(http.MethodPost, "/api/admin/packages/create", bytes.NewReader(validPayload))
	recValid := httptest.NewRecorder()
	createHandler.ServeHTTP(recValid, reqValid)
	if recValid.Code != http.StatusCreated && recValid.Code != http.StatusOK {
		t.Fatalf("expected HTTP 201 when creating package with multi-user node, got %d: %s", recValid.Code, recValid.Body.String())
	}
}
