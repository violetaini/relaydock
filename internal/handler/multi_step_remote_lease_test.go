package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/storage"
)

type credentialMigrationLeaseAgent struct {
	requests      atomic.Int64
	removeStarted chan struct{}
	releaseRemove <-chan struct{}
	removeOnce    sync.Once
}

func (a *credentialMigrationLeaseAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/api/child/inbounds" {
		http.NotFound(w, r)
		return
	}
	a.requests.Add(1)
	var payload struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}
	if payload.Action == "remove-client" && a.removeStarted != nil {
		a.removeOnce.Do(func() { close(a.removeStarted) })
		if a.releaseRemove != nil {
			<-a.releaseRemove
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "changed": true})
}

func createCredentialMigrationFixture(t *testing.T, agent http.Handler) (*storage.TrafficRepository, *storage.RemoteServer, *CredentialEmailMigrator, storage.UserInboundConfig) {
	t.Helper()
	agentServer := httptest.NewServer(agent)
	t.Cleanup(agentServer.Close)
	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agentServer.URL))
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "alice", "alice@example.test", "alice", "test-hash", storage.RoleUser, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveUserInboundConfig(ctx, storage.UserInboundConfig{
		Username:       "alice",
		ServerID:       server.ID,
		InboundTag:     "vless-in",
		Protocol:       "vless",
		CredentialJSON: `{"id":"alice-id","email":"alice@example.test"}`,
	}); err != nil {
		t.Fatal(err)
	}
	config, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "vless-in")
	if err != nil {
		t.Fatal(err)
	}
	return repo, server, NewCredentialEmailMigrator(repo, NewRemoteManageHandler(repo, nil)), *config
}

func TestCredentialMigrationActiveInstallDoesNotTouchAgentOrDatabase(t *testing.T) {
	agent := &credentialMigrationLeaseAgent{}
	repo, server, migrator, config := createCredentialMigrationFixture(t, agent)
	ctx := context.Background()
	if err := repo.BeginRemoteServerInstallation(ctx, server.ID, "credential-active-install", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	err := migrator.migrateOne(ctx, config)
	if !errors.Is(err, storage.ErrRemoteInstallationActive) {
		t.Fatalf("migrateOne error=%v, want ErrRemoteInstallationActive", err)
	}
	if got := agent.requests.Load(); got != 0 {
		t.Fatalf("active installation reached Agent %d time(s)", got)
	}
	stored, err := repo.GetUserInboundConfig(ctx, "alice", server.ID, "vless-in")
	if err != nil {
		t.Fatal(err)
	}
	if stored.CredentialJSON != config.CredentialJSON {
		t.Fatalf("active installation changed credential: %s", stored.CredentialJSON)
	}
}

func TestCredentialMigrationRejectsNegativeAgentACK(t *testing.T) {
	var requests atomic.Int64
	agent := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": false,
			"error":   "credential mutation rejected",
		})
	})
	repo, _, migrator, config := createCredentialMigrationFixture(t, agent)
	if err := migrator.migrateOne(context.Background(), config); err == nil || !strings.Contains(err.Error(), "credential mutation rejected") {
		t.Fatalf("migrateOne error=%v, want negative Agent ACK", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("negative ACK caused %d Agent requests, want one", got)
	}
	stored, err := repo.GetUserInboundConfig(context.Background(), "alice", config.ServerID, "vless-in")
	if err != nil {
		t.Fatal(err)
	}
	if stored.CredentialJSON != config.CredentialJSON {
		t.Fatalf("negative ACK changed credential: %s", stored.CredentialJSON)
	}
}

func TestInstallationBeginWaitsForCompleteCredentialMigration(t *testing.T) {
	removeStarted := make(chan struct{})
	releaseRemove := make(chan struct{})
	agent := &credentialMigrationLeaseAgent{removeStarted: removeStarted, releaseRemove: releaseRemove}
	repo, server, migrator, config := createCredentialMigrationFixture(t, agent)

	migrateDone := make(chan error, 1)
	go func() { migrateDone <- migrator.migrateOne(context.Background(), config) }()
	select {
	case <-removeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("credential migration did not reach remove-client")
	}

	beginDone := make(chan error, 1)
	go func() {
		beginDone <- repo.BeginRemoteServerInstallation(context.Background(), server.ID, "credential-waiting-install", time.Now().Add(time.Minute))
	}()
	select {
	case err := <-beginDone:
		t.Fatalf("installation Begin returned inside credential migration: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(releaseRemove)
	if err := <-migrateDone; err != nil {
		t.Fatalf("migrateOne: %v", err)
	}
	select {
	case err := <-beginDone:
		if err != nil {
			t.Fatalf("Begin after migration: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Begin remained blocked after migration committed")
	}
	stored, err := repo.GetUserInboundConfig(context.Background(), "alice", server.ID, "vless-in")
	if err != nil {
		t.Fatal(err)
	}
	var credential map[string]any
	if err := json.Unmarshal([]byte(stored.CredentialJSON), &credential); err != nil {
		t.Fatal(err)
	}
	if credential["email"] != "alice__vless-in" {
		t.Fatalf("Begin acquired before DB commit: credential=%s", stored.CredentialJSON)
	}
	if got := agent.requests.Load(); got != 2 {
		t.Fatalf("migration Agent requests=%d, want remove+add", got)
	}
}

type routedCreateLeaseAgent struct {
	mutationRequests atomic.Int64
	ruleStarted      chan struct{}
	releaseRule      <-chan struct{}
	ruleOnce         sync.Once
}

func (a *routedCreateLeaseAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/inbounds":
		a.mutationRequests.Add(1)
		_, _ = w.Write([]byte(`{"success":true,"inbounds":[{"tag":"vless-in","settings":{"clients":[{"id":"owner-id","email":"owner","flow":"xtls-rprx-vision"}]}}]}`))
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/inbounds":
		a.mutationRequests.Add(1)
		_, _ = w.Write([]byte(`{"success":true,"changed":true}`))
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/outbounds":
		a.mutationRequests.Add(1)
		_, _ = w.Write([]byte(`{"success":true,"changed":true}`))
	case r.Method == http.MethodPost && r.URL.Path == "/api/child/routing":
		a.mutationRequests.Add(1)
		var payload struct {
			Action string `json:"action"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		if payload.Action == "add_rule" && a.ruleStarted != nil {
			a.ruleOnce.Do(func() { close(a.ruleStarted) })
			if a.releaseRule != nil {
				<-a.releaseRule
			}
		}
		_, _ = w.Write([]byte(`{"success":true,"changed":true}`))
	case r.Method == http.MethodGet && r.URL.Path == "/api/child/xray/config":
		_, _ = w.Write([]byte(`{"success":true,"config":"{}"}`))
	default:
		http.NotFound(w, r)
	}
}

func TestInstallationBeginWaitsForRoutedCreateAndActiveDeleteIsFailClosed(t *testing.T) {
	ruleStarted := make(chan struct{})
	releaseRule := make(chan struct{})
	agent := &routedCreateLeaseAgent{ruleStarted: ruleStarted, releaseRule: releaseRule}
	agentServer := httptest.NewServer(agent)
	defer agentServer.Close()
	repo, server := newRemoteInstallationHandlerRepo(t, testServerPort(t, agentServer.URL))
	ctx := context.Background()
	if err := repo.CreateUser(ctx, "owner", "owner@example.test", "owner", "test-hash", storage.RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	parent, err := repo.CreateNode(ctx, storage.Node{
		Username:       "owner",
		NodeName:       "parent",
		Protocol:       "vless",
		ClashConfig:    `{"name":"parent","type":"vless","server":"edge.example.test","port":443,"uuid":"owner-id"}`,
		Enabled:        true,
		OriginalServer: server.Name,
		InboundTag:     "vless-in",
		NodeType:       "physical",
	})
	if err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(createRoutedOutboundReq{
		ParentNodeID: parent.ID,
		Label:        "lease-test",
		Outbound:     map[string]any{"protocol": "freedom", "settings": map[string]any{}},
	})
	request := httptest.NewRequest(http.MethodPost, "/api/admin/nodes/routed-outbound", bytes.NewReader(body))
	response := httptest.NewRecorder()
	handlerDone := make(chan struct{})
	go func() {
		NewRoutedOutboundHandler(repo, NewRemoteManageHandler(repo, nil)).ServeHTTP(response, request)
		close(handlerDone)
	}()
	select {
	case <-ruleStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("routed create did not reach routing mutation")
	}

	beginDone := make(chan error, 1)
	go func() {
		beginDone <- repo.BeginRemoteServerInstallation(context.Background(), server.ID, "routed-create-waiting-install", time.Now().Add(time.Minute))
	}()
	select {
	case err := <-beginDone:
		t.Fatalf("installation Begin returned inside routed create: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseRule)
	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("routed create did not finish")
	}
	if response.Code != http.StatusOK {
		t.Fatalf("routed create status=%d body=%s", response.Code, response.Body.String())
	}
	select {
	case err := <-beginDone:
		if err != nil {
			t.Fatalf("Begin after routed create: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Begin remained blocked after routed create committed")
	}

	routed, err := repo.ListRoutedNodesByParent(ctx, parent.ID)
	if err != nil || len(routed) != 1 {
		t.Fatalf("routed DB commit missing: nodes=%d err=%v", len(routed), err)
	}
	beforeDelete := agent.mutationRequests.Load()
	deleteRequest := httptest.NewRequest(http.MethodDelete, "/api/admin/nodes/routed-outbound?id="+jsonNumber(routed[0].ID), nil)
	deleteResponse := httptest.NewRecorder()
	NewRoutedOutboundHandler(repo, NewRemoteManageHandler(repo, nil)).ServeHTTP(deleteResponse, deleteRequest)
	if deleteResponse.Code != http.StatusConflict {
		t.Fatalf("active-install delete status=%d body=%s", deleteResponse.Code, deleteResponse.Body.String())
	}
	if got := agent.mutationRequests.Load(); got != beforeDelete {
		t.Fatalf("active-install delete reached Agent: before=%d after=%d", beforeDelete, got)
	}
	if _, err := repo.GetRoutedNodeDetail(ctx, routed[0].ID); err != nil {
		t.Fatalf("active-install delete changed DB: %v", err)
	}
}

func jsonNumber(value int64) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
