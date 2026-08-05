package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

type managedRealityCompatibilityMutation struct {
	Action     string                 `json:"action"`
	Inbound    map[string]interface{} `json:"inbound"`
	MutationID string                 `json:"mutation_id"`
}

func managedRealityCompatibilityTestInbound(tag, mutationID string, fenceKnown bool, minClientVer interface{}) map[string]interface{} {
	realitySettings := map[string]interface{}{}
	if minClientVer != nil {
		realitySettings["minClientVer"] = minClientVer
	}
	return map[string]interface{}{
		"tag":                   tag,
		"protocol":              "vless",
		"port":                  2443,
		"_mutation_fence_known": fenceKnown,
		"_mutation_id":          mutationID,
		"settings":              map[string]interface{}{"clients": []interface{}{}},
		"streamSettings": map[string]interface{}{
			"security":        "reality",
			"realitySettings": realitySettings,
		},
	}
}

func managedRealityCompatibilityMinClientVer(t *testing.T, inbound map[string]interface{}) interface{} {
	t.Helper()
	streamSettings, ok := inbound["streamSettings"].(map[string]interface{})
	if !ok {
		t.Fatalf("replacement inbound has no streamSettings: %#v", inbound)
	}
	realitySettings, ok := streamSettings["realitySettings"].(map[string]interface{})
	if !ok {
		t.Fatalf("replacement inbound has no realitySettings: %#v", inbound)
	}
	return realitySettings["minClientVer"]
}

func TestManagedRealityCompatibilityHotReplacesOwnedRealityOnly(t *testing.T) {
	ownedMissing := managedRealityCompatibilityTestInbound("panel-reality-missing", "panel-generation-missing", true, nil)
	ownedBlank := managedRealityCompatibilityTestInbound("panel-reality-blank", "panel-generation-blank", true, " \t")
	unowned := managedRealityCompatibilityTestInbound("user-reality", "user-generation", true, " ")

	var mutationMu sync.Mutex
	mutations := make([]managedRealityCompatibilityMutation, 0, 2)
	var controlCalls atomic.Int32
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success":              true,
				"mutation_fence_known": true,
				"mutation_owners": map[string]string{
					"panel-reality-missing": "panel-generation-missing",
					"panel-reality-blank":   "panel-generation-blank",
					"user-reality":          "user-generation",
				},
				"inbounds": []map[string]interface{}{ownedMissing, ownedBlank, unowned},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
			var mutation managedRealityCompatibilityMutation
			if err := json.NewDecoder(r.Body).Decode(&mutation); err != nil {
				http.Error(w, `{"success":false,"error":"invalid mutation"}`, http.StatusBadRequest)
				return
			}
			mutationMu.Lock()
			mutations = append(mutations, mutation)
			mutationMu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success":     true,
				"changed":     true,
				"mutation_id": mutation.MutationID,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/child/services/control":
			controlCalls.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		case r.Method == http.MethodGet && r.URL.Path == "/api/child/xray/config":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "config": `{}`})
		default:
			http.NotFound(w, r)
		}
	}))
	defer agent.Close()

	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
	if err := repo.SetRemoteInboundOwnership(context.Background(), server.ID, "panel-reality-missing", "panel-generation-missing"); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetRemoteInboundOwnership(context.Background(), server.ID, "panel-reality-blank", "panel-generation-blank"); err != nil {
		t.Fatal(err)
	}
	handler := NewRemoteManageHandler(repo, nil)
	request := httptest.NewRequest(http.MethodPost, "/api/admin/remote/xray/reality-compatibility?server_id="+strconv.FormatInt(server.ID, 10), nil)
	response := httptest.NewRecorder()

	handler.HandleManagedRealityCompatibility(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Success bool `json:"success"`
		Updated int  `json:"updated"`
		Skipped int  `json:"skipped"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if !result.Success || result.Updated != 2 || result.Skipped != 1 {
		t.Fatalf("result=%+v, want success with two updates and one skipped inbound", result)
	}

	mutationMu.Lock()
	defer mutationMu.Unlock()
	if len(mutations) != 2 {
		t.Fatalf("hot replacements=%d, want 2", len(mutations))
	}
	wantMutations := map[string]string{
		"panel-reality-missing": "panel-generation-missing",
		"panel-reality-blank":   "panel-generation-blank",
	}
	for _, mutation := range mutations {
		tag, _ := mutation.Inbound["tag"].(string)
		wantMutationID, known := wantMutations[tag]
		if !known || mutation.Action != "add" || mutation.MutationID != wantMutationID {
			t.Fatalf("replacement=%+v, want only panel-owned inbound replacements", mutation)
		}
		if got := managedRealityCompatibilityMinClientVer(t, mutation.Inbound); got != managedRealityMinClientVersion {
			t.Fatalf("replacement minClientVer=%#v, want %q", got, managedRealityMinClientVersion)
		}
		if _, leaked := mutation.Inbound["_mutation_id"]; leaked {
			t.Fatalf("Agent replacement unexpectedly included mutation metadata: %#v", mutation.Inbound)
		}
		delete(wantMutations, tag)
	}
	if len(wantMutations) != 0 {
		t.Fatalf("missing panel-owned replacements for %#v", wantMutations)
	}
	if got := controlCalls.Load(); got != 0 {
		t.Fatalf("full Xray restart requests=%d, want 0", got)
	}
}

func TestManagedRealityCompatibilitySkipsWithoutAuthoritativeOwnership(t *testing.T) {
	for _, test := range []struct {
		name                string
		inventoryFenceKnown bool
		inboundFenceKnown   bool
		storedOwnership     string
	}{
		{
			name:                "Agent does not support the mutation fence",
			inventoryFenceKnown: false,
			inboundFenceKnown:   true,
			storedOwnership:     "panel-generation",
		},
		{
			name:                "control plane has no ownership record",
			inventoryFenceKnown: true,
			inboundFenceKnown:   true,
		},
		{
			name:                "inbound does not expose its mutation fence",
			inventoryFenceKnown: true,
			inboundFenceKnown:   false,
			storedOwnership:     "panel-generation",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			inbound := managedRealityCompatibilityTestInbound("panel-reality", "panel-generation", test.inboundFenceKnown, nil)
			var inboundMutationCalls atomic.Int32
			var controlCalls atomic.Int32
			agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
					_ = json.NewEncoder(w).Encode(map[string]interface{}{
						"success":              true,
						"mutation_fence_known": test.inventoryFenceKnown,
						"mutation_owners":      map[string]string{"panel-reality": "panel-generation"},
						"inbounds":             []map[string]interface{}{inbound},
					})
				case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
					inboundMutationCalls.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "mutation_id": "panel-generation"})
				case r.Method == http.MethodPost && r.URL.Path == "/api/child/services/control":
					controlCalls.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
				default:
					http.NotFound(w, r)
				}
			}))
			defer agent.Close()

			repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agent.URL))
			if test.storedOwnership != "" {
				if err := repo.SetRemoteInboundOwnership(context.Background(), server.ID, "panel-reality", test.storedOwnership); err != nil {
					t.Fatal(err)
				}
			}
			handler := NewRemoteManageHandler(repo, nil)
			request := httptest.NewRequest(http.MethodPost, "/api/admin/remote/xray/reality-compatibility?server_id="+strconv.FormatInt(server.ID, 10), nil)
			response := httptest.NewRecorder()

			handler.HandleManagedRealityCompatibility(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var result struct {
				Success bool `json:"success"`
				Updated int  `json:"updated"`
				Skipped int  `json:"skipped"`
			}
			if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
				t.Fatal(err)
			}
			if !result.Success || result.Updated != 0 || result.Skipped != 1 {
				t.Fatalf("result=%+v, want success with one skipped inbound", result)
			}
			if got := inboundMutationCalls.Load(); got != 0 {
				t.Fatalf("inbound mutation requests=%d, want 0", got)
			}
			if got := controlCalls.Load(); got != 0 {
				t.Fatalf("full Xray restart requests=%d, want 0", got)
			}
		})
	}
}
