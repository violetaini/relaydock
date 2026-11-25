package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/violetaini/relaydock/internal/auth"
	"github.com/violetaini/relaydock/internal/logger"
	"github.com/violetaini/relaydock/internal/storage"
)

func generationFixture(t *testing.T) (*storage.TrafficRepository, storage.SubscribeFile) {
	t.Helper()
	l := logger.GetLogger()
	previous := l.Logger
	l.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Cleanup(func() { l.Logger = previous })
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("subscribes", 0700); err != nil {
		t.Fatal(err)
	}
	repo := newManagedSecurityTestRepo(t)
	createManagedSecurityTestUser(t, repo, "admin", storage.RoleAdmin)
	createManagedSecurityTestUser(t, repo, "alice", storage.RoleUser)
	source, err := repo.CreateSubscribeFile(context.Background(), storage.SubscribeFile{Name: "机场", Type: storage.SubscribeTypeUpload, Filename: "airport.yaml", CreatedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	raw := `proxies:
 - {name: HKT, type: ss, server: icable.example.net, port: 443, cipher: aes-128-gcm, password: secret}
proxy-groups:
 - {name: Proxy, type: select, proxies: [HKT]}
rules:
 - MATCH,Proxy
`
	if err := os.WriteFile("subscribes/airport.yaml", []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	return repo, source
}
func generationRecipe(ids ...int64) *storage.SubscriptionGeneration {
	return &storage.SubscriptionGeneration{Kind: "strategy", SourceIDs: ids, Processing: storage.SubscriptionProcessing{Deduplicate: true, Sort: "source"}, Outputs: []storage.SubscriptionOutput{{Client: "clashmeta", Mode: "full", TemplateFilename: builtInSubscriptionTemplate}}}
}
func generationCall(repo *storage.TrafficRepository, path string, req generationRequest) *httptest.ResponseRecorder {
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	r = r.WithContext(auth.ContextWithUsername(r.Context(), "admin"))
	w := httptest.NewRecorder()
	NewSubscribeFilesHandler(repo).ServeHTTP(w, r)
	return w
}

func TestGenerationPersistsRecipeAndFollowsExternalSource(t *testing.T) {
	repo, source := generationFixture(t)
	req := generationRequest{Name: "日常订阅", Filename: "combined.yaml", Generation: generationRecipe(source.ID)}
	w := generationCall(repo, "/api/admin/subscribe-files/generation", req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create status=%d: %s", w.Code, w.Body.String())
	}
	files, err := repo.ListSubscribeFiles(context.Background())
	if err != nil || len(files) != 2 {
		t.Fatalf("files=%d err=%v", len(files), err)
	}
	combined, err := repo.GetSubscribeFileByFilename(context.Background(), "combined.yaml")
	if err != nil || combined.Generation == nil || combined.Generation.SourceIDs[0] != source.ID {
		t.Fatalf("recipe was not persisted: %v", err)
	}
	before, _ := os.ReadFile("subscribes/airport.yaml")
	if err := os.WriteFile("subscribes/airport.yaml", bytes.ReplaceAll(before, []byte("icable.example.net"), []byte("new-ddns.example.net")), 0600); err != nil {
		t.Fatal(err)
	}
	h := NewSubscriptionHandlerConcrete(repo, "subscribes")
	data, _, err := h.generateSubscription(context.Background(), combined, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "new-ddns.example.net") || strings.Contains(string(data), "icable.example.net") {
		t.Fatal("recipe did not follow the source update")
	}
	if err := repo.DeleteSubscribeFile(context.Background(), source.ID, source.Filename); err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.generateSubscription(context.Background(), combined, ""); err == nil {
		t.Fatal("deleted source was served from a stale combined snapshot")
	}
}

func TestGenerationCombinesImportedAndManagedNodes(t *testing.T) {
	repo, source := generationFixture(t)
	node, err := repo.CreateNode(context.Background(), storage.Node{Username: "admin", NodeName: "自建 DMIT", Protocol: "ss", Enabled: true, ClashConfig: `{"name":"自建 DMIT","type":"ss","server":"managed.example.net","port":8443,"cipher":"aes-128-gcm","password":"different"}`})
	if err != nil {
		t.Fatal(err)
	}
	custom, err := repo.CreateSubscribeFile(context.Background(), storage.SubscribeFile{Name: "自建专线", Type: storage.SubscribeTypeCreate, Filename: "managed.yaml", CreatedBy: "admin", SelectedNodeIDs: []int64{node.ID}, Generation: &storage.SubscriptionGeneration{Kind: "custom", Processing: storage.SubscriptionProcessing{}, Outputs: []storage.SubscriptionOutput{{Client: "clashmeta", Mode: "nodes"}}}})
	if err != nil {
		t.Fatal(err)
	}
	recipe := storage.SubscribeFile{CreatedBy: "admin", Generation: generationRecipe(source.ID, custom.ID)}
	data, stats, err := NewSubscriptionHandlerConcrete(repo, "subscribes").generateSubscription(context.Background(), recipe, "")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Output != 2 || !bytes.Contains(data, []byte("managed.example.net")) || !bytes.Contains(data, []byte("icable.example.net")) {
		t.Fatalf("combined output=%d missing a source", stats.Output)
	}
}

func TestGenerationRejectsForeignNestedAndSelfSources(t *testing.T) {
	repo, source := generationFixture(t)
	h := NewSubscriptionHandlerConcrete(repo, "subscribes")
	tests := []storage.SubscribeFile{
		{CreatedBy: "alice", Generation: generationRecipe(source.ID)},
		{ID: source.ID, CreatedBy: "admin", Generation: generationRecipe(source.ID)},
		{CreatedBy: "admin", Generation: generationRecipe(source.ID, source.ID)},
	}
	for _, f := range tests {
		if _, _, err := h.generateSubscription(context.Background(), f, ""); err == nil {
			t.Fatal("invalid/foreign source accepted")
		}
	}
	nested, err := repo.CreateSubscribeFile(context.Background(), storage.SubscribeFile{Name: "Nested", Type: "create", Filename: "nested.yaml", CreatedBy: "admin", Generation: generationRecipe(source.ID)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.generateSubscription(context.Background(), storage.SubscribeFile{CreatedBy: "admin", Generation: generationRecipe(nested.ID)}, ""); err == nil {
		t.Fatal("nested strategy accepted")
	}
}

func TestGenerationPreservesSingleSourceRulesWithoutChangingOriginal(t *testing.T) {
	repo, source := generationFixture(t)
	before, _ := os.ReadFile("subscribes/airport.yaml")
	g := generationRecipe(source.ID)
	g.Outputs[0] = storage.SubscriptionOutput{Client: "clashmeta", Mode: "source"}
	data, stats, err := NewSubscriptionHandlerConcrete(repo, "subscribes").generateSubscription(context.Background(), storage.SubscribeFile{CreatedBy: "admin", Generation: g}, "")
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile("subscribes/airport.yaml")
	if !bytes.Equal(before, after) || stats.Output != 1 || !bytes.Contains(data, []byte("MATCH,Proxy")) {
		t.Fatal("source rules or original content lost")
	}
	g.SourceIDs = append(g.SourceIDs, source.ID)
	if _, _, err := NewSubscriptionHandlerConcrete(repo, "subscribes").generateSubscription(context.Background(), storage.SubscribeFile{CreatedBy: "admin", Generation: g}, ""); err == nil {
		t.Fatal("multiple sources allowed upstream-rule inheritance")
	}
}

func TestGenerationHealthRequiresThreeFailuresAndRecovers(t *testing.T) {
	repo, source := generationFixture(t)
	h := NewSubscriptionHandlerConcrete(repo, "subscribes")
	g := generationRecipe(source.ID)
	g.Processing.RemoveDead = true
	f := storage.SubscribeFile{CreatedBy: "admin", Generation: g}
	nodes, _, err := h.generationSources(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	key := generationFingerprint(nodes[0])
	for i := 0; i < 3; i++ {
		if err := repo.RecordSubscriptionNodeHealth(context.Background(), "admin", key, false, 0); err != nil {
			t.Fatal(err)
		}
	}
	// A total outage must not clear the exported subscription.
	_, stats, err := h.generateSubscription(context.Background(), f, "")
	if err != nil || stats.Output != 1 || len(stats.Warnings) == 0 {
		t.Fatalf("total outage protection failed: %+v %v", stats, err)
	}
	if err := repo.RecordSubscriptionNodeHealth(context.Background(), "admin", key, true, 32); err != nil {
		t.Fatal(err)
	}
	_, stats, err = h.generateSubscription(context.Background(), f, "")
	if err != nil || stats.Output != 1 || len(stats.Warnings) != 0 {
		t.Fatalf("node did not recover: %+v %v", stats, err)
	}
}

func TestGenerationValidatesEveryOutputBeforeWriting(t *testing.T) {
	repo, source := generationFixture(t)
	g := generationRecipe(source.ID)
	g.Outputs = append(g.Outputs, storage.SubscriptionOutput{Client: "v2ray", Mode: "full", TemplateFilename: builtInSubscriptionTemplate})
	w := generationCall(repo, "/api/admin/subscribe-files/generation", generationRequest{Name: "Invalid", Filename: "invalid.yaml", Generation: g})
	if w.Code != 422 {
		t.Fatalf("invalid output status=%d", w.Code)
	}
	if _, err := os.Stat("subscribes/invalid.yaml"); !os.IsNotExist(err) {
		t.Fatal("failed output created an orphan file")
	}
	files, _ := repo.ListSubscribeFiles(context.Background())
	if len(files) != 1 {
		t.Fatal("failed output created a database row")
	}
	g.Outputs = g.Outputs[:1]
	g.Outputs[0].TemplateFilename = "missing.yaml"
	w = generationCall(repo, "/api/admin/subscribe-files/generation", generationRequest{Name: "Missing", Filename: "invalid.yaml", Generation: g})
	if w.Code != 422 {
		t.Fatal("missing template accepted")
	}
}

func TestGenerationMultipleClientsProduceNativeConfigurations(t *testing.T) {
	repo, source := generationFixture(t)
	g := generationRecipe(source.ID)
	g.Outputs = append(g.Outputs, storage.SubscriptionOutput{Client: "clash-to-shadowrocket", Mode: "full", TemplateFilename: builtInSubscriptionTemplate}, storage.SubscriptionOutput{Client: "v2ray", Mode: "nodes"}, storage.SubscriptionOutput{Client: "sing-box", Mode: "full", TemplateFilename: builtInSubscriptionTemplate})
	w := generationCall(repo, "/api/admin/subscribe-files/generation/preview", generationRequest{Generation: g})
	if w.Code != 200 {
		t.Fatalf("preview status=%d: %s", w.Code, w.Body.String())
	}
	var result generationPreview
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Outputs) != 4 {
		t.Fatalf("outputs=%d", len(result.Outputs))
	}
	if !strings.Contains(result.Outputs[1].Content, "[Rule]") || !strings.Contains(result.Outputs[1].Content, "[Proxy]") {
		t.Fatal("Shadowrocket lost its full configuration")
	}
	decoded, err := base64.StdEncoding.DecodeString(result.Outputs[2].Content)
	if err != nil || !strings.Contains(string(decoded), "ss://") {
		t.Fatal("V2Ray output is not a URI subscription")
	}
	var native map[string]any
	if err := json.Unmarshal([]byte(result.Outputs[3].Content), &native); err != nil || native["route"] == nil || native["dns"] == nil || native["inbounds"] == nil {
		t.Fatalf("sing-box output silently dropped routing: %v", err)
	}
}

func TestGenerationNormalizationKeepsRawRulesAndAcceptsBase64(t *testing.T) {
	raw := []byte("proxies: []\nrules: [MATCH,DIRECT]\n")
	normalized, err := normalizeImportedSubscription(raw)
	if err != nil || !bytes.Equal(raw, normalized) {
		t.Fatal("YAML original was not preserved")
	}
	uri := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:secret")) + "@ddns.example.net:443#HKT"
	normalized, err = normalizeImportedSubscription([]byte(base64.StdEncoding.EncodeToString([]byte(uri))))
	if err != nil || !bytes.Contains(normalized, []byte("ddns.example.net")) {
		t.Fatalf("base64 import failed: %v", err)
	}
	if _, err := normalizeImportedSubscription([]byte("<html>login</html>")); err == nil {
		t.Fatal("HTML accepted as subscription")
	}
}

func TestGenerationRouteExportUsesURIClientTemplateAndRequiresLogin(t *testing.T) {
	repo, source := generationFixture(t)
	g := generationRecipe(source.ID)
	g.Outputs[0].TemplateFilename = "unrelated-clash-template.yaml"
	g.Outputs = append(g.Outputs, storage.SubscriptionOutput{Client: "v2ray", Mode: "nodes", TemplateFilename: builtInSubscriptionTemplate})
	f, err := repo.CreateSubscribeFile(context.Background(), storage.SubscribeFile{Name: "Routing", Filename: "routing.yaml", Type: storage.SubscribeTypeCreate, CreatedBy: "admin", Generation: g})
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/admin/subscribe-files/" + strconv.FormatInt(f.ID, 10) + "/routes"
	for _, principal := range []string{"", "alice", "admin"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		if principal != "" {
			r = r.WithContext(auth.ContextWithUsername(r.Context(), principal))
		}
		w := httptest.NewRecorder()
		NewSubscribeFilesHandler(repo).ServeHTTP(w, r)
		want := map[string]int{"": 401, "alice": 404, "admin": 200}[principal]
		if w.Code != want {
			t.Fatalf("principal=%q status=%d: %s", principal, w.Code, w.Body.String())
		}
		if principal == "admin" {
			var native map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &native); err != nil || native["rules"] == nil || !strings.Contains(w.Body.String(), "direct") {
				t.Fatalf("missing native route rules: %v", err)
			}
		}
	}
}

func TestGenerationRemovesOnlyRepeatedlyFailingNodes(t *testing.T) {
	repo, source := generationFixture(t)
	raw, _ := os.ReadFile("subscribes/airport.yaml")
	raw = bytes.Replace(raw, []byte("proxy-groups:"), []byte(" - {name: Live, type: ss, server: live.example.net, port: 443, cipher: aes-128-gcm, password: other}\nproxy-groups:"), 1)
	if err := os.WriteFile("subscribes/airport.yaml", raw, 0600); err != nil {
		t.Fatal(err)
	}
	h := NewSubscriptionHandlerConcrete(repo, "subscribes")
	g := generationRecipe(source.ID)
	g.Processing.RemoveDead = true
	f := storage.SubscribeFile{CreatedBy: "admin", Generation: g}
	nodes, _, err := h.generationSources(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := repo.RecordSubscriptionNodeHealth(context.Background(), "admin", generationFingerprint(nodes[0]), false, 0); err != nil {
			t.Fatal(err)
		}
		data, stats, err := h.generateSubscription(context.Background(), f, "")
		want := 2
		if i == 2 {
			want = 1
		}
		if err != nil || stats.Output != want || !bytes.Contains(data, []byte("live.example.net")) {
			t.Fatalf("failure=%d stats=%+v err=%v", i+1, stats, err)
		}
	}
}

func TestGenerationGlobalAPIUsesDurableAdminOwner(t *testing.T) {
	repo, _ := generationFixture(t)
	node, err := repo.CreateNode(context.Background(), storage.Node{Username: "admin", NodeName: "Managed", Protocol: "vless", Enabled: true, OriginalServer: "Managed", InboundTag: "managed-in", ClashConfig: `{"name":"Managed","type":"vless","server":"managed.example.net","port":443,"uuid":"secret"}`})
	if err != nil {
		t.Fatal(err)
	}
	g := generationRecipe()
	g.Kind = "custom"
	preview := generationCall(repo, "/api/admin/subscribe-files/generation/preview", generationRequest{SelectedNodeIDs: []int64{node.ID}, Generation: g})
	if preview.Code != http.StatusOK {
		t.Fatalf("preview without name/filename status=%d: %s", preview.Code, preview.Body.String())
	}
	req := generationRequest{Name: "API owned", Filename: "api-owned.yaml", SelectedNodeIDs: []int64{node.ID}, Generation: g}
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "/api/admin/subscribe-files/generation", bytes.NewReader(body))
	r = r.WithContext(auth.ContextWithGlobalAPIToken(r.Context()))
	w := httptest.NewRecorder()
	NewSubscribeFilesHandler(repo).ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("global API status=%d: %s", w.Code, w.Body.String())
	}
	f, err := repo.GetSubscribeFileByFilename(context.Background(), "api-owned.yaml")
	if err != nil || f.CreatedBy != "admin" {
		t.Fatalf("recipe owner=%q err=%v", f.CreatedBy, err)
	}
	if _, _, err := NewSubscriptionHandlerConcrete(repo, "subscribes").generateSubscription(context.Background(), f, ""); err != nil {
		t.Fatalf("background regeneration lost its owner: %v", err)
	}
}

func TestGenerationSortByTypeCustomOrderAndDirection(t *testing.T) {
	repo, source := generationFixture(t)
	raw := `proxies:
 - {name: Z-VMess, type: vmess, server: vmess.example.net, port: 443, uuid: 11111111-1111-1111-1111-111111111111}
 - {name: A-SS, type: ss, server: ss.example.net, port: 443, cipher: aes-128-gcm, password: secret}
 - {name: M-Trojan, type: trojan, server: trojan.example.net, port: 443, password: secret}
`
	if err := os.WriteFile("subscribes/airport.yaml", []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}

	h := NewSubscriptionHandlerConcrete(repo, "subscribes")
	g := generationRecipe(source.ID)
	g.Outputs = []storage.SubscriptionOutput{{Client: "clashmeta", Mode: "nodes"}}

	// 1. Sort by type ascending: ss -> trojan -> vmess
	g.Processing.Sort = "type"
	g.Processing.SortDirection = "asc"
	_, stats, err := h.generateSubscription(context.Background(), storage.SubscribeFile{CreatedBy: "admin", Generation: g}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.Nodes) != 3 || stats.Nodes[0].Type != "ss" || stats.Nodes[1].Type != "trojan" || stats.Nodes[2].Type != "vmess" {
		t.Fatalf("type asc order wrong: %+v", stats.Nodes)
	}

	// 2. Sort by type descending: vmess -> trojan -> ss
	g.Processing.SortDirection = "desc"
	_, stats, err = h.generateSubscription(context.Background(), storage.SubscribeFile{CreatedBy: "admin", Generation: g}, "")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Nodes[0].Type != "vmess" || stats.Nodes[1].Type != "trojan" || stats.Nodes[2].Type != "ss" {
		t.Fatalf("type desc order wrong: %+v", stats.Nodes)
	}

	// 2b. Sort by custom type_order: vmess -> trojan -> ss (and reverse)
	g.Processing.Sort = "type"
	g.Processing.SortDirection = "asc"
	g.Processing.TypeOrder = []string{"vmess", "trojan", "ss"}
	_, stats, err = h.generateSubscription(context.Background(), storage.SubscribeFile{CreatedBy: "admin", Generation: g}, "")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Nodes[0].Type != "vmess" || stats.Nodes[1].Type != "trojan" || stats.Nodes[2].Type != "ss" {
		t.Fatalf("custom type_order asc wrong: %+v", stats.Nodes)
	}

	// 3. Custom order by key (M-Trojan -> Z-VMess -> A-SS) + reverse toggle
	g.Processing.TypeOrder = nil
	trojanKey := stats.Nodes[1].Key
	vmessKey := stats.Nodes[0].Key
	g.Processing.Sort = "custom"
	g.Processing.SortDirection = "asc"
	g.Processing.CustomOrder = []string{trojanKey, vmessKey}
	_, stats, err = h.generateSubscription(context.Background(), storage.SubscribeFile{CreatedBy: "admin", Generation: g}, "")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Nodes[0].Name != "M-Trojan" || stats.Nodes[1].Name != "Z-VMess" || stats.Nodes[2].Name != "A-SS" {
		t.Fatalf("custom asc order wrong: %+v", stats.Nodes)
	}

	g.Processing.SortDirection = "desc"
	_, stats, err = h.generateSubscription(context.Background(), storage.SubscribeFile{CreatedBy: "admin", Generation: g}, "")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Nodes[0].Name != "A-SS" || stats.Nodes[1].Name != "Z-VMess" || stats.Nodes[2].Name != "M-Trojan" {
		t.Fatalf("custom desc order wrong: %+v", stats.Nodes)
	}
}

func TestGenerationSortByRegionAndServerCountryCode(t *testing.T) {
	repo, source := generationFixture(t)
	ctx := context.Background()

	// Server bound by domain, initial region set to SG and must stay SG even if IP changes.
	srv := &storage.RemoteServer{Name: "sg-edge", Token: "tok-sg", Domain: "sg.example.net", IPAddress: "203.0.113.50", XrayMode: "embedded"}
	if err := repo.CreateRemoteServer(ctx, srv); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetRemoteServerCountryCodeIfEmpty(ctx, srv.ID, "SG"); err != nil {
		t.Fatal(err)
	}
	// Attempting to overwrite when already set (simulating dynamic IP change) must be a no-op.
	if err := repo.SetRemoteServerCountryCodeIfEmpty(ctx, srv.ID, "US"); err != nil {
		t.Fatal(err)
	}
	loaded, err := repo.GetRemoteServer(ctx, srv.ID)
	if err != nil || loaded.CountryCode != "SG" {
		t.Fatalf("expected initial server country_code SG to persist across dynamic IP updates, got %q err=%v", loaded.CountryCode, err)
	}

	// Admin updates server region explicitly to JP via UpdateRemoteServerCountryCode.
	if err := repo.UpdateRemoteServerCountryCode(ctx, srv.ID, "JP"); err != nil {
		t.Fatal(err)
	}
	loaded, _ = repo.GetRemoteServer(ctx, srv.ID)
	if loaded.CountryCode != "JP" {
		t.Fatalf("expected admin-updated country_code JP, got %q", loaded.CountryCode)
	}

	raw := `proxies:
  - {name: Alpha Node, type: ss, server: sg.example.net, port: 443, cipher: aes-128-gcm, password: a}
  - {name: 香港 HKT 01, type: vmess, server: hk.example.net, port: 443, uuid: 11111111-1111-1111-1111-111111111111}
  - {name: 🇺🇸 US West, type: trojan, server: us.example.net, port: 443, password: b}
`
	if err := os.WriteFile("subscribes/airport.yaml", []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	h := NewSubscriptionHandlerConcrete(repo, "subscribes")
	g := generationRecipe(source.ID)
	g.Processing.Sort = "region"
	g.Processing.SortDirection = "asc"
	g.Processing.RegionOrder = []string{"US", "HK", "JP"}

	_, stats, err := h.generateSubscription(ctx, storage.SubscribeFile{CreatedBy: "admin", Generation: g}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.Nodes) != 3 ||
		stats.Nodes[0].CountryCode != "US" ||
		stats.Nodes[1].CountryCode != "HK" ||
		stats.Nodes[2].CountryCode != "JP" {
		t.Fatalf("region asc sort wrong: %+v", stats.Nodes)
	}

	g.Processing.SortDirection = "desc"
	_, stats, err = h.generateSubscription(ctx, storage.SubscribeFile{CreatedBy: "admin", Generation: g}, "")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Nodes[0].CountryCode != "JP" || stats.Nodes[1].CountryCode != "HK" || stats.Nodes[2].CountryCode != "US" {
		t.Fatalf("region desc sort wrong: %+v", stats.Nodes)
	}
}
