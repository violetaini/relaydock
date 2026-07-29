package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/proxyman/command"
	"google.golang.org/grpc"
)

func TestChildXrayServiceLifecycleSerializesInboundMutations(t *testing.T) {
	for _, action := range []string{"start", "stop", "restart"} {
		t.Run(action, func(t *testing.T) {
			serviceEntered := make(chan struct{})
			serviceRelease := make(chan struct{})
			handler := &ChildManageHandler{
				inboundMutationFencePath: filepath.Join(t.TempDir(), "inbound-fences.json"),
				inboundMutationFences:    make(map[string]inboundMutationFenceState),
				serviceControlCommand: func(service, actualAction string) ([]byte, error) {
					if service != "xray" || actualAction != action {
						t.Errorf("unexpected service control: %s %s", service, actualAction)
						return nil, errors.New("unexpected service control")
					}
					close(serviceEntered)
					<-serviceRelease
					return nil, nil
				},
			}

			response := httptest.NewRecorder()
			body := fmt.Sprintf(`{"service":"xray","action":%q}`, action)
			request := httptest.NewRequest(http.MethodPost, "/api/child/services/control", strings.NewReader(body))
			requestDone := make(chan struct{})
			go func() {
				handler.HandleServiceControl(response, request)
				close(requestDone)
			}()

			select {
			case <-serviceEntered:
			case <-time.After(time.Second):
				t.Fatalf("Xray %s did not begin", action)
			}

			mutationEntered := make(chan struct{})
			go func() {
				handler.inboundsMu.Lock()
				close(mutationEntered)
				handler.inboundsMu.Unlock()
			}()
			select {
			case <-mutationEntered:
				t.Fatalf("inbound mutation entered while Xray %s was in progress", action)
			case <-time.After(100 * time.Millisecond):
			}

			close(serviceRelease)
			select {
			case <-requestDone:
			case <-time.After(time.Second):
				t.Fatalf("Xray %s request did not finish", action)
			}
			select {
			case <-mutationEntered:
			case <-time.After(time.Second):
				t.Fatalf("inbound mutation remained blocked after Xray %s", action)
			}
			if response.Code != http.StatusOK {
				t.Fatalf("%s response status = %d, body = %s", action, response.Code, response.Body.String())
			}
		})
	}
}

func TestChildXrayCertificateDeploymentSerializesInboundMutations(t *testing.T) {
	directory := t.TempDir()
	serviceEntered := make(chan struct{})
	serviceRelease := make(chan struct{})
	handler := &ChildManageHandler{
		inboundMutationFencePath: filepath.Join(directory, "inbound-fences.json"),
		inboundMutationFences:    make(map[string]inboundMutationFenceState),
		serviceControlCommand: func(service, action string) ([]byte, error) {
			if service != "xray" || action != "restart" {
				return nil, fmt.Errorf("unexpected service control: %s %s", service, action)
			}
			close(serviceEntered)
			<-serviceRelease
			return nil, nil
		},
	}
	certPath := filepath.Join(directory, "tls", "certificate.pem")
	keyPath := filepath.Join(directory, "tls", "certificate.key")
	deployDone := make(chan error, 1)
	go func() {
		deployDone <- handler.DeployCertificateFiles("certificate", "private-key", certPath, keyPath, "xray")
	}()

	select {
	case <-serviceEntered:
	case <-time.After(time.Second):
		t.Fatal("certificate-triggered Xray restart did not begin")
	}
	if content, err := os.ReadFile(certPath); err != nil || string(content) != "certificate" {
		t.Fatalf("certificate was not written before restart: content=%q err=%v", content, err)
	}
	if content, err := os.ReadFile(keyPath); err != nil || string(content) != "private-key" {
		t.Fatalf("private key was not written before restart: content=%q err=%v", content, err)
	}

	mutationEntered := make(chan struct{})
	go func() {
		handler.inboundsMu.Lock()
		close(mutationEntered)
		handler.inboundsMu.Unlock()
	}()
	select {
	case <-mutationEntered:
		t.Fatal("inbound mutation entered during certificate deployment")
	case <-time.After(100 * time.Millisecond):
	}

	close(serviceRelease)
	select {
	case err := <-deployDone:
		if err != nil {
			t.Fatalf("DeployCertificateFiles: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("certificate deployment did not finish")
	}
	select {
	case <-mutationEntered:
	case <-time.After(time.Second):
		t.Fatal("inbound mutation remained blocked after certificate deployment")
	}
}

type inboundMutationFenceHandlerClient struct {
	command.HandlerServiceClient
	addCalls    int
	failAddCall int
	removeCalls int
	failRemove  bool
}

func (client *inboundMutationFenceHandlerClient) AddInbound(
	_ context.Context,
	_ *command.AddInboundRequest,
	_ ...grpc.CallOption,
) (*command.AddInboundResponse, error) {
	client.addCalls++
	if client.addCalls == client.failAddCall {
		return nil, errors.New("synthetic gRPC add failure")
	}
	return &command.AddInboundResponse{}, nil
}

func (client *inboundMutationFenceHandlerClient) RemoveInbound(
	_ context.Context,
	_ *command.RemoveInboundRequest,
	_ ...grpc.CallOption,
) (*command.RemoveInboundResponse, error) {
	client.removeCalls++
	if client.failRemove {
		return nil, errors.New("synthetic gRPC remove failure")
	}
	return &command.RemoveInboundResponse{}, nil
}

func TestChildInboundMutationFenceRejectsLateAddAfterPersistedRemove(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "inbound-fences.json")
	configPath := filepath.Join(directory, "config.json")
	writeInboundPersistenceFixture(t, configPath, nil)
	first := &ChildManageHandler{inboundMutationFencePath: path, inboundMutationFences: make(map[string]inboundMutationFenceState)}
	first.inboundsMu.Lock()
	skip, _, err := first.beginInboundMutationLocked("remove", &ChildInboundRequest{Tag: "tunnel-race-h0", MutationID: "operation-old"})
	first.inboundsMu.Unlock()
	if err != nil || skip {
		t.Fatalf("begin remove skip=%v err=%v", skip, err)
	}

	// Simulate a new Agent process receiving the delayed add after the remove
	// already acknowledged. The sidecar tombstone must still reject it.
	second := &ChildManageHandler{inboundMutationFencePath: path, inboundMutationFences: make(map[string]inboundMutationFenceState)}
	second.inboundsMu.Lock()
	_, err = second.beginInboundAddMutationLocked(&ChildInboundRequest{
		MutationID: "operation-old",
		Inbound:    map[string]interface{}{"tag": "tunnel-race-h0"},
	}, configPath, nil)
	second.inboundsMu.Unlock()
	if err == nil {
		t.Fatal("late add unexpectedly passed the persisted remove fence")
	}

	second.inboundsMu.Lock()
	intended := map[string]interface{}{"tag": "tunnel-race-h0"}
	transaction, err := second.beginInboundAddMutationLocked(&ChildInboundRequest{
		MutationID: "operation-new",
		Inbound:    intended,
	}, configPath, nil)
	if err == nil {
		writeInboundPersistenceFixture(t, configPath, []any{intended})
		err = second.commitInboundMutationLocked(transaction)
	}
	skip, _, removeErr := second.beginInboundMutationLocked("remove", &ChildInboundRequest{Tag: "tunnel-race-h0", MutationID: "operation-old"})
	second.inboundsMu.Unlock()
	if err != nil {
		t.Fatalf("new mutation was rejected: %v", err)
	}
	if removeErr != nil || !skip {
		t.Fatalf("old remove must not delete newer mutation: skip=%v err=%v", skip, removeErr)
	}
}

func TestChildInboundMutationFenceRejectsUnfencedRemoveOfOwnedTag(t *testing.T) {
	handler := &ChildManageHandler{
		inboundMutationFencePath: filepath.Join(t.TempDir(), "inbound-fences.json"),
		inboundMutationFences:    make(map[string]inboundMutationFenceState),
	}
	handler.inboundsMu.Lock()
	addErr := seedChildInboundMutationOwner(handler, "same-tag", "generation-new")
	_, _, removeErr := handler.beginInboundMutationLocked("remove", &ChildInboundRequest{Tag: "same-tag"})
	handler.inboundsMu.Unlock()
	if addErr != nil {
		t.Fatalf("add fence: %v", addErr)
	}
	if removeErr == nil {
		t.Fatal("empty mutation_id unexpectedly removed an owned tag")
	}
}

func TestChildInboundMutationFenceAllowsLegacyRemoveWithoutOwner(t *testing.T) {
	handler := &ChildManageHandler{
		inboundMutationFencePath: filepath.Join(t.TempDir(), "inbound-fences.json"),
		inboundMutationFences:    make(map[string]inboundMutationFenceState),
	}
	handler.inboundsMu.Lock()
	skip, _, err := handler.beginInboundMutationLocked("remove", &ChildInboundRequest{Tag: "legacy-tag"})
	handler.inboundsMu.Unlock()
	if err != nil || skip {
		t.Fatalf("legacy unfenced remove skip=%v err=%v", skip, err)
	}
}

func TestChildInboundMutationFenceConditionalReplacementCAS(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	previousInbound := mutationFenceTestInbound("legacy-wireguard", 51820)
	intendedInbound := mutationFenceTestInbound("legacy-wireguard", 51821)
	writeInboundPersistenceFixture(t, configPath, []any{previousInbound})
	previousDigest, err := canonicalInboundMutationDigest(previousInbound)
	if err != nil {
		t.Fatal(err)
	}
	emptyOwner := ""

	handler := &ChildManageHandler{
		inboundMutationFencePath: filepath.Join(directory, "inbound-fences.json"),
		inboundMutationFences:    make(map[string]inboundMutationFenceState),
	}
	handler.inboundsMu.Lock()
	transaction, err := handler.beginInboundAddMutationLocked(&ChildInboundRequest{
		MutationID:            "managed-wireguard:legacy-generation",
		ExpectedMutationOwner: &emptyOwner,
		ExpectedInboundDigest: previousDigest,
		Inbound:               intendedInbound,
	}, configPath, previousInbound)
	if err == nil {
		err = handler.rollbackInboundMutationLocked(transaction)
	}
	handler.inboundsMu.Unlock()
	if err != nil {
		t.Fatalf("matching conditional replacement failed: %v", err)
	}

	handler.inboundsMu.Lock()
	if err := seedChildInboundMutationOwner(handler, "legacy-wireguard", "managed-wireguard:newer-generation"); err != nil {
		handler.inboundsMu.Unlock()
		t.Fatal(err)
	}
	_, ownerErr := handler.beginInboundAddMutationLocked(&ChildInboundRequest{
		MutationID:            "managed-wireguard:legacy-generation",
		ExpectedMutationOwner: &emptyOwner,
		ExpectedInboundDigest: previousDigest,
		Inbound:               intendedInbound,
	}, configPath, previousInbound)
	handler.inboundsMu.Unlock()
	if ownerErr == nil || !strings.Contains(ownerErr.Error(), "owner changed") {
		t.Fatalf("changed owner was not rejected: %v", ownerErr)
	}

	digestHandler := &ChildManageHandler{
		inboundMutationFencePath: filepath.Join(directory, "digest-inbound-fences.json"),
		inboundMutationFences:    make(map[string]inboundMutationFenceState),
	}
	digestHandler.inboundsMu.Lock()
	_, digestErr := digestHandler.beginInboundAddMutationLocked(&ChildInboundRequest{
		MutationID:            "managed-wireguard:legacy-generation",
		ExpectedMutationOwner: &emptyOwner,
		ExpectedInboundDigest: strings.Repeat("0", 64),
		Inbound:               intendedInbound,
	}, configPath, previousInbound)
	digestHandler.inboundsMu.Unlock()
	if digestErr == nil || !strings.Contains(digestErr.Error(), "changed before conditional replacement") {
		t.Fatalf("changed inbound digest was not rejected: %v", digestErr)
	}
}

func TestApplyInboundAddRestoresPreviousFenceOnEveryFailurePhase(t *testing.T) {
	for _, phase := range []string{"grpc", "persist", "firewall"} {
		t.Run(phase, func(t *testing.T) {
			directory := t.TempDir()
			configPath := filepath.Join(directory, "config.json")
			oldInbound := mutationFenceTestInbound("same-tag", 21001)
			newInbound := mutationFenceTestInbound("same-tag", 21002)
			writeInboundPersistenceFixture(t, configPath, []any{oldInbound})

			handler := &ChildManageHandler{
				inboundMutationFencePath: filepath.Join(directory, "inbound-fences.json"),
				inboundMutationFences:    make(map[string]inboundMutationFenceState),
			}
			err := seedChildInboundMutationOwner(handler, "same-tag", "generation-old")
			if err != nil {
				t.Fatalf("seed old owner: %v", err)
			}

			runtimeClient := &inboundMutationFenceHandlerClient{}
			if phase == "grpc" {
				runtimeClient.failAddCall = 1
			}
			if phase == "persist" {
				configPath = filepath.Join(directory, "missing", "config.json")
			}
			if phase == "firewall" {
				firewallCalls := 0
				handler.inboundFirewallSync = func(context.Context) error {
					firewallCalls++
					if firewallCalls == 1 {
						return errors.New("synthetic firewall failure")
					}
					return nil
				}
			}

			err = handler.applyInboundAddLocked(context.Background(), runtimeClient, configPath, &ChildInboundRequest{
				MutationID: "generation-new",
				Inbound:    newInbound,
			}, oldInbound)
			if err == nil {
				t.Fatalf("%s failure unexpectedly succeeded", phase)
			}
			assertInboundMutationOwnerRestored(t, handler.inboundMutationFencePath, "same-tag", "generation-old", "generation-new")
		})
	}
}

func TestApplyInboundAddCommitsFenceAfterAllPhasesSucceed(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	oldInbound := mutationFenceTestInbound("same-tag", 22001)
	newInbound := mutationFenceTestInbound("same-tag", 22002)
	writeInboundPersistenceFixture(t, configPath, []any{oldInbound})
	handler := &ChildManageHandler{
		inboundMutationFencePath: filepath.Join(directory, "inbound-fences.json"),
		inboundMutationFences:    make(map[string]inboundMutationFenceState),
	}
	err := seedChildInboundMutationOwner(handler, "same-tag", "generation-old")
	if err != nil {
		t.Fatalf("seed old owner: %v", err)
	}
	if err := handler.applyInboundAddLocked(context.Background(), &inboundMutationFenceHandlerClient{}, configPath, &ChildInboundRequest{
		MutationID: "generation-new",
		Inbound:    newInbound,
	}, oldInbound); err != nil {
		t.Fatalf("apply successful add: %v", err)
	}

	reloaded := &ChildManageHandler{
		inboundMutationFencePath: handler.inboundMutationFencePath,
		inboundMutationFences:    make(map[string]inboundMutationFenceState),
	}
	if err := reloaded.ensureInboundMutationFencesLocked(); err != nil {
		t.Fatalf("reload mutation fence: %v", err)
	}
	if got := reloaded.inboundMutationFences["same-tag"].Owner; got != "generation-new" {
		t.Fatalf("owner=%q want generation-new", got)
	}
	if skip, _, err := reloaded.beginInboundMutationLocked("remove", &ChildInboundRequest{Tag: "same-tag", MutationID: "generation-old"}); err != nil || !skip {
		t.Fatalf("old generation delete must be superseded: skip=%v err=%v", skip, err)
	}
	if skip, _, err := reloaded.beginInboundMutationLocked("remove", &ChildInboundRequest{Tag: "same-tag", MutationID: "generation-new"}); err != nil || skip {
		t.Fatalf("new generation delete must remain valid: skip=%v err=%v", skip, err)
	}
}

func TestApplyInboundAddRetainsNewFenceWhenRollbackIsUnresolved(t *testing.T) {
	directory := t.TempDir()
	missingConfig := filepath.Join(directory, "missing", "config.json")
	handler := &ChildManageHandler{
		inboundMutationFencePath: filepath.Join(directory, "inbound-fences.json"),
		inboundMutationFences:    make(map[string]inboundMutationFenceState),
	}
	client := &inboundMutationFenceHandlerClient{failRemove: true}
	request := &ChildInboundRequest{
		MutationID: "generation-new",
		Inbound:    mutationFenceTestInbound("same-tag", 23001),
	}
	if err := handler.applyInboundAddLocked(context.Background(), client, missingConfig, request, nil); err == nil {
		t.Fatal("persistence and rollback failure unexpectedly succeeded")
	}

	reloaded := &ChildManageHandler{
		inboundMutationFencePath: handler.inboundMutationFencePath,
		inboundMutationFences:    make(map[string]inboundMutationFenceState),
	}
	if err := reloaded.resolvePendingInboundMutationsLocked(func(_ string, _ string, _ map[string]interface{}, present bool) error {
		if present {
			return errors.New("expected absent durable inbound")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if state, exists := reloaded.inboundMutationFences["same-tag"]; exists && (state.Owner != "" || state.Pending != nil) {
		t.Fatalf("restart should restore absent durable generation, got %#v", state)
	}
}

func TestChildInboundMutationPendingBeforeConfigWriteRestoresPreviousOwner(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	path := filepath.Join(directory, "inbound-fences.json")
	previous := mutationFenceTestInbound("same-tag", 24001)
	intended := mutationFenceTestInbound("same-tag", 24002)
	writeInboundPersistenceFixture(t, configPath, []any{previous})

	handler := &ChildManageHandler{inboundMutationFencePath: path, inboundMutationFences: make(map[string]inboundMutationFenceState)}
	if err := seedChildInboundMutationOwner(handler, "same-tag", "generation-old"); err != nil {
		t.Fatal(err)
	}
	if _, err := handler.beginInboundAddMutationLocked(&ChildInboundRequest{
		MutationID: "generation-new",
		Inbound:    intended,
	}, configPath, previous); err != nil {
		t.Fatalf("reserve pending mutation: %v", err)
	}

	reloaded := &ChildManageHandler{inboundMutationFencePath: path, inboundMutationFences: make(map[string]inboundMutationFenceState)}
	converged := false
	if err := reloaded.resolvePendingInboundMutationsLocked(func(_ string, tag string, inbound map[string]interface{}, present bool) error {
		converged = present && tag == "same-tag" && inbound != nil
		return nil
	}); err != nil {
		t.Fatalf("recover pre-config crash: %v", err)
	}
	if !converged {
		t.Fatal("previous durable inbound was not replayed to runtime before recovery")
	}
	state := reloaded.inboundMutationFences["same-tag"]
	if state.Owner != "generation-old" || state.Pending != nil {
		t.Fatalf("recovered state=%#v want committed previous owner", state)
	}
}

func TestChildInboundMutationPendingAfterConfigWriteCommitsIntendedOwner(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	path := filepath.Join(directory, "inbound-fences.json")
	previous := mutationFenceTestInbound("same-tag", 25001)
	intended := mutationFenceTestInbound("same-tag", 25002)
	writeInboundPersistenceFixture(t, configPath, []any{previous})

	handler := &ChildManageHandler{inboundMutationFencePath: path, inboundMutationFences: make(map[string]inboundMutationFenceState)}
	if err := seedChildInboundMutationOwner(handler, "same-tag", "generation-old"); err != nil {
		t.Fatal(err)
	}
	if _, err := handler.beginInboundAddMutationLocked(&ChildInboundRequest{
		MutationID: "generation-new",
		Inbound:    intended,
	}, configPath, previous); err != nil {
		t.Fatalf("reserve pending mutation: %v", err)
	}
	writeInboundPersistenceFixture(t, configPath, []any{intended})

	reloaded := &ChildManageHandler{inboundMutationFencePath: path, inboundMutationFences: make(map[string]inboundMutationFenceState)}
	converged := false
	if err := reloaded.resolvePendingInboundMutationsLocked(func(_ string, tag string, inbound map[string]interface{}, present bool) error {
		converged = present && tag == "same-tag" && inbound != nil
		return nil
	}); err != nil {
		t.Fatalf("recover post-config crash: %v", err)
	}
	if !converged {
		t.Fatal("intended durable inbound was not replayed to runtime before recovery")
	}
	state := reloaded.inboundMutationFences["same-tag"]
	if state.Owner != "generation-new" || state.Pending != nil {
		t.Fatalf("recovered state=%#v want committed intended owner", state)
	}
}

func TestChildInboundMutationRuntimeFirstCrashStaysPendingUntilRuntimeConverges(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	path := filepath.Join(directory, "inbound-fences.json")
	previous := mutationFenceTestInbound("same-tag", 25501)
	intended := mutationFenceTestInbound("same-tag", 25502)
	writeInboundPersistenceFixture(t, configPath, []any{previous})

	handler := &ChildManageHandler{inboundMutationFencePath: path, inboundMutationFences: make(map[string]inboundMutationFenceState)}
	if err := seedChildInboundMutationOwner(handler, "same-tag", "generation-old"); err != nil {
		t.Fatal(err)
	}
	if _, err := handler.beginInboundAddMutationLocked(&ChildInboundRequest{
		MutationID: "generation-new",
		Inbound:    intended,
	}, configPath, previous); err != nil {
		t.Fatal(err)
	}

	// Simulate a crash after runtime accepted intended but before config write.
	// Disk still contains previous. Failed runtime replay must not clear pending.
	reloaded := &ChildManageHandler{inboundMutationFencePath: path, inboundMutationFences: make(map[string]inboundMutationFenceState)}
	if err := reloaded.resolvePendingInboundMutationsLocked(func(_ string, _ string, _ map[string]interface{}, _ bool) error {
		return errors.New("synthetic runtime convergence failure")
	}); err == nil {
		t.Fatal("failed runtime convergence unexpectedly published previous owner")
	}
	state := reloaded.inboundMutationFences["same-tag"]
	if state.Owner != "generation-old" || state.Pending == nil {
		t.Fatalf("state=%#v want previous owner plus pending WAL", state)
	}
	if err := reloaded.ensureInboundMutationFencesLocked(); err == nil {
		t.Fatal("ordinary mutation path did not fail closed while recovery was pending")
	}
	if err := reloaded.resolvePendingInboundMutationsLocked(func(_ string, _ string, inbound map[string]interface{}, present bool) error {
		if !present || inbound == nil {
			return errors.New("previous durable inbound was not supplied")
		}
		return nil
	}); err != nil {
		t.Fatalf("retry runtime convergence: %v", err)
	}
	state = reloaded.inboundMutationFences["same-tag"]
	if state.Owner != "generation-old" || state.Pending != nil {
		t.Fatalf("recovered state=%#v", state)
	}
}

func TestChildInboundMutationCommitVerifiesDurableIntendedDigest(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	path := filepath.Join(directory, "inbound-fences.json")
	previous := mutationFenceTestInbound("same-tag", 25701)
	intended := mutationFenceTestInbound("same-tag", 25702)
	writeInboundPersistenceFixture(t, configPath, []any{previous})
	handler := &ChildManageHandler{inboundMutationFencePath: path, inboundMutationFences: make(map[string]inboundMutationFenceState)}
	if err := seedChildInboundMutationOwner(handler, "same-tag", "generation-old"); err != nil {
		t.Fatal(err)
	}
	transaction, err := handler.beginInboundAddMutationLocked(&ChildInboundRequest{
		MutationID: "generation-new",
		Inbound:    intended,
	}, configPath, previous)
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.commitInboundMutationLocked(transaction); err == nil {
		t.Fatal("commit accepted previous durable config as intended generation")
	}
	state := handler.inboundMutationFences["same-tag"]
	if state.Owner != "generation-old" || state.Pending == nil {
		t.Fatalf("state=%#v want pending fail-closed recovery", state)
	}
}

func TestChildInboundMutationPendingMismatchFailsInventoryClosed(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	path := filepath.Join(directory, "inbound-fences.json")
	previous := mutationFenceTestInbound("same-tag", 26001)
	intended := mutationFenceTestInbound("same-tag", 26002)
	writeInboundPersistenceFixture(t, configPath, []any{previous})

	handler := &ChildManageHandler{inboundMutationFencePath: path, inboundMutationFences: make(map[string]inboundMutationFenceState)}
	if err := seedChildInboundMutationOwner(handler, "same-tag", "generation-old"); err != nil {
		t.Fatal(err)
	}
	if _, err := handler.beginInboundAddMutationLocked(&ChildInboundRequest{
		MutationID: "generation-new",
		Inbound:    intended,
	}, configPath, previous); err != nil {
		t.Fatalf("reserve pending mutation: %v", err)
	}
	writeInboundPersistenceFixture(t, configPath, []any{mutationFenceTestInbound("same-tag", 26999)})

	reloaded := &ChildManageHandler{inboundMutationFencePath: path, inboundMutationFences: make(map[string]inboundMutationFenceState)}
	if err := reloaded.ensureInboundMutationFencesLocked(); err == nil {
		t.Fatal("mismatched durable config unexpectedly published an owner")
	}
	recorder := httptest.NewRecorder()
	reloaded.listInbounds(recorder, httptest.NewRequest(http.MethodGet, "/api/child/inbounds", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("inventory status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if state := reloaded.inboundMutationFences["same-tag"]; state.Pending == nil {
		t.Fatal("ambiguous recovery discarded pending WAL")
	}
}

func TestChildInboundMutationPendingRejectsActiveConfigPathSwitch(t *testing.T) {
	directory := t.TempDir()
	oldConfigPath := filepath.Join(directory, "old", "config.json")
	newConfigPath := filepath.Join(directory, "new", "config.json")
	path := filepath.Join(directory, "state", inboundMutationFenceSidecarName)
	previous := mutationFenceTestInbound("same-tag", 26501)
	intended := mutationFenceTestInbound("same-tag", 26502)
	if err := os.MkdirAll(filepath.Dir(oldConfigPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(newConfigPath), 0700); err != nil {
		t.Fatal(err)
	}
	writeInboundPersistenceFixture(t, oldConfigPath, []any{previous})
	writeInboundPersistenceFixture(t, newConfigPath, []any{mutationFenceTestInbound("same-tag", 26599)})

	handler := &ChildManageHandler{inboundMutationFencePath: path, inboundMutationFences: make(map[string]inboundMutationFenceState)}
	if err := seedChildInboundMutationOwner(handler, "same-tag", "generation-old"); err != nil {
		t.Fatal(err)
	}
	if _, err := handler.beginInboundAddMutationLocked(&ChildInboundRequest{
		MutationID: "generation-new",
		Inbound:    intended,
	}, oldConfigPath, previous); err != nil {
		t.Fatal(err)
	}
	writeInboundPersistenceFixture(t, oldConfigPath, []any{intended})

	converged := false
	reloaded := &ChildManageHandler{
		inboundMutationFencePath: path,
		inboundMutationFences:    make(map[string]inboundMutationFenceState),
		inboundMutationActiveConfig: func() string {
			return newConfigPath
		},
	}
	if err := reloaded.resolvePendingInboundMutationsLocked(func(_ string, _ string, _ map[string]interface{}, _ bool) error {
		converged = true
		return nil
	}); err == nil {
		t.Fatal("inactive old config unexpectedly recovered and published an owner")
	}
	if converged {
		t.Fatal("runtime convergence used an inactive Xray config")
	}
	state := reloaded.inboundMutationFences["same-tag"]
	if state.Owner != "generation-old" || state.Pending == nil {
		t.Fatalf("state=%#v want fail-closed pending WAL", state)
	}
}

func TestChildInboundMutationFenceMigratesV1Sidecar(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inbound-fences.json")
	legacy := map[string]interface{}{
		"version": 1,
		"tags": map[string]interface{}{
			"same-tag": map[string]interface{}{
				"owner":    "generation-old",
				"canceled": []string{"generation-removed"},
			},
		},
	}
	content, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	handler := &ChildManageHandler{inboundMutationFencePath: path, inboundMutationFences: make(map[string]inboundMutationFenceState)}
	if err := handler.ensureInboundMutationFencesLocked(); err != nil {
		t.Fatalf("migrate v1 sidecar: %v", err)
	}
	content, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var migrated inboundMutationFenceFile
	if err := json.Unmarshal(content, &migrated); err != nil {
		t.Fatal(err)
	}
	if migrated.Version != inboundMutationFenceVersion || migrated.Tags["same-tag"].Owner != "generation-old" {
		t.Fatalf("migrated sidecar=%#v", migrated)
	}
}

func TestChildInboundMutationFenceMigratesLegacyPathsToStableState(t *testing.T) {
	root := t.TempDir()
	stablePath := filepath.Join(root, "data", inboundMutationFenceSidecarName)
	legacyFirst := filepath.Join(root, "usr-local-xray", inboundMutationFenceSidecarName)
	legacySecond := filepath.Join(root, "etc-xray", inboundMutationFenceSidecarName)
	writeChildInboundMutationFenceFixture(t, legacyFirst, 1, map[string]inboundMutationFenceState{
		"same-tag": {
			Owner:    "generation-new",
			Canceled: map[string]struct{}{"generation-old": {}},
		},
	})
	writeChildInboundMutationFenceFixture(t, legacySecond, inboundMutationFenceVersion, map[string]inboundMutationFenceState{
		"other-tag": {Owner: "other-generation", Canceled: make(map[string]struct{})},
	})

	handler := &ChildManageHandler{
		inboundMutationFencePath:   stablePath,
		inboundMutationLegacyPaths: []string{legacyFirst, legacySecond},
		inboundMutationFences:      make(map[string]inboundMutationFenceState),
	}
	if err := handler.ensureInboundMutationFencesLocked(); err != nil {
		t.Fatalf("migrate legacy sidecars: %v", err)
	}
	if got := handler.inboundMutationFences["same-tag"].Owner; got != "generation-new" {
		t.Fatalf("same-tag owner=%q", got)
	}
	if got := handler.inboundMutationFences["other-tag"].Owner; got != "other-generation" {
		t.Fatalf("other-tag owner=%q", got)
	}
	for _, legacyPath := range []string{legacyFirst, legacySecond} {
		if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
			t.Fatalf("legacy sidecar %s was not removed: %v", legacyPath, err)
		}
	}
	if _, err := os.Stat(stablePath); err != nil {
		t.Fatalf("stable sidecar missing: %v", err)
	}

	// Simulate an Xray config priority/path switch. Only the stable Child state
	// remains, so a delayed old-generation remove must still be superseded.
	reloaded := &ChildManageHandler{
		inboundMutationFencePath:   stablePath,
		inboundMutationLegacyPaths: []string{filepath.Join(root, "opt-xray", inboundMutationFenceSidecarName)},
		inboundMutationFences:      make(map[string]inboundMutationFenceState),
	}
	if err := reloaded.ensureInboundMutationFencesLocked(); err != nil {
		t.Fatal(err)
	}
	skip, _, err := reloaded.beginInboundMutationLocked("remove", &ChildInboundRequest{
		Tag:        "same-tag",
		MutationID: "generation-old",
	})
	if err != nil || !skip {
		t.Fatalf("stale remove after path switch skip=%v err=%v", skip, err)
	}
}

func TestChildInboundMutationFenceLegacyOwnerConflictFailsClosed(t *testing.T) {
	root := t.TempDir()
	stablePath := filepath.Join(root, "data", inboundMutationFenceSidecarName)
	legacyPath := filepath.Join(root, "legacy", inboundMutationFenceSidecarName)
	writeChildInboundMutationFenceFixture(t, stablePath, inboundMutationFenceVersion, map[string]inboundMutationFenceState{
		"same-tag": {Owner: "generation-a", Canceled: make(map[string]struct{})},
	})
	writeChildInboundMutationFenceFixture(t, legacyPath, 1, map[string]inboundMutationFenceState{
		"same-tag": {Owner: "generation-b", Canceled: make(map[string]struct{})},
	})
	handler := &ChildManageHandler{
		inboundMutationFencePath:   stablePath,
		inboundMutationLegacyPaths: []string{legacyPath},
		inboundMutationFences:      make(map[string]inboundMutationFenceState),
	}
	if err := handler.ensureInboundMutationFencesLocked(); err == nil {
		t.Fatal("conflicting legacy owner unexpectedly loaded")
	}
	if handler.inboundMutationFencesLoaded {
		t.Fatal("conflicting migration published an authoritative in-memory owner")
	}
}

func TestChildInboundMutationReservationRestoresAfterAppliedRenameError(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	path := filepath.Join(directory, "inbound-fences.json")
	previous := mutationFenceTestInbound("same-tag", 27001)
	intended := mutationFenceTestInbound("same-tag", 27002)
	writeInboundPersistenceFixture(t, configPath, []any{previous})
	handler := &ChildManageHandler{inboundMutationFencePath: path, inboundMutationFences: make(map[string]inboundMutationFenceState)}
	if err := seedChildInboundMutationOwner(handler, "same-tag", "generation-old"); err != nil {
		t.Fatal(err)
	}
	writes := 0
	handler.inboundMutationFenceWriter = func(path string, value interface{}) error {
		writes++
		if err := writeJSONFileAtomic(path, value); err != nil {
			return err
		}
		if writes == 1 {
			return &atomicRenameAppliedError{err: errors.New("synthetic parent sync failure")}
		}
		return nil
	}
	if _, err := handler.beginInboundAddMutationLocked(&ChildInboundRequest{
		MutationID: "generation-new",
		Inbound:    intended,
	}, configPath, previous); err == nil {
		t.Fatal("reservation unexpectedly ignored applied rename durability error")
	}
	if writes != 2 {
		t.Fatalf("sidecar writes=%d want pending plus durable rollback", writes)
	}
	reloaded := &ChildManageHandler{inboundMutationFencePath: path, inboundMutationFences: make(map[string]inboundMutationFenceState)}
	if err := reloaded.ensureInboundMutationFencesLocked(); err != nil {
		t.Fatal(err)
	}
	state := reloaded.inboundMutationFences["same-tag"]
	if state.Owner != "generation-old" || state.Pending != nil {
		t.Fatalf("state=%#v want restored previous owner", state)
	}
}

func TestChildInboundMutationCommitKeepsAppliedRenameState(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.json")
	path := filepath.Join(directory, "inbound-fences.json")
	previous := mutationFenceTestInbound("same-tag", 28001)
	intended := mutationFenceTestInbound("same-tag", 28002)
	writeInboundPersistenceFixture(t, configPath, []any{previous})
	handler := &ChildManageHandler{inboundMutationFencePath: path, inboundMutationFences: make(map[string]inboundMutationFenceState)}
	if err := seedChildInboundMutationOwner(handler, "same-tag", "generation-old"); err != nil {
		t.Fatal(err)
	}
	transaction, err := handler.beginInboundAddMutationLocked(&ChildInboundRequest{
		MutationID: "generation-new",
		Inbound:    intended,
	}, configPath, previous)
	if err != nil {
		t.Fatal(err)
	}
	writeInboundPersistenceFixture(t, configPath, []any{intended})
	handler.inboundMutationFenceWriter = func(path string, value interface{}) error {
		if err := writeJSONFileAtomic(path, value); err != nil {
			return err
		}
		return &atomicRenameAppliedError{err: errors.New("synthetic parent sync failure")}
	}
	if err := handler.commitInboundMutationLocked(transaction); err == nil {
		t.Fatal("commit unexpectedly hid durability error")
	}
	state := handler.inboundMutationFences["same-tag"]
	if state.Owner != "generation-new" || state.Pending != nil {
		t.Fatalf("memory state=%#v want applied committed owner", state)
	}
	reloaded := &ChildManageHandler{inboundMutationFencePath: path, inboundMutationFences: make(map[string]inboundMutationFenceState)}
	if err := reloaded.ensureInboundMutationFencesLocked(); err != nil {
		t.Fatal(err)
	}
	if got := reloaded.inboundMutationFences["same-tag"].Owner; got != "generation-new" {
		t.Fatalf("reloaded owner=%q", got)
	}
}

func TestInboundRuntimeAbsentErrorIsIdempotentOnlyForNotFound(t *testing.T) {
	if !isInboundRuntimeAbsentError(errors.New("handler not found: same-tag")) {
		t.Fatal("not-found runtime error was not treated as absent")
	}
	if isInboundRuntimeAbsentError(errors.New("transport timeout")) {
		t.Fatal("transport failure was incorrectly treated as absent")
	}
}

func seedChildInboundMutationOwner(handler *ChildManageHandler, tag, owner string) error {
	if err := handler.ensureInboundMutationFencesLocked(); err != nil {
		return err
	}
	candidate := cloneInboundMutationFenceStates(handler.inboundMutationFences)
	candidate[tag] = inboundMutationFenceState{Owner: owner, Canceled: make(map[string]struct{})}
	if err := handler.persistInboundMutationFenceStatesLocked(candidate); err != nil {
		return err
	}
	handler.inboundMutationFences = candidate
	return nil
}

func writeChildInboundMutationFenceFixture(t *testing.T, path string, version int, states map[string]inboundMutationFenceState) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	file := inboundMutationFenceFileFromStates(states)
	file.Version = version
	if err := writeJSONFileAtomic(path, file); err != nil {
		t.Fatal(err)
	}
}

func mutationFenceTestInbound(tag string, port int) map[string]any {
	return map[string]any{
		"tag":      tag,
		"listen":   "127.0.0.1",
		"port":     port,
		"protocol": "dokodemo-door",
		"settings": map[string]any{
			"address": "127.0.0.1",
			"port":    80,
			"network": "tcp",
		},
	}
}

func assertInboundMutationOwnerRestored(t *testing.T, path, tag, oldMutationID, failedMutationID string) {
	t.Helper()
	reloaded := &ChildManageHandler{
		inboundMutationFencePath: path,
		inboundMutationFences:    make(map[string]inboundMutationFenceState),
	}
	if err := reloaded.ensureInboundMutationFencesLocked(); err != nil {
		t.Fatalf("reload mutation fence: %v", err)
	}
	if got := reloaded.inboundMutationFences[tag].Owner; got != oldMutationID {
		t.Fatalf("owner=%q want restored %q", got, oldMutationID)
	}
	if skip, _, err := reloaded.beginInboundMutationLocked("remove", &ChildInboundRequest{Tag: tag, MutationID: failedMutationID}); err != nil || !skip {
		t.Fatalf("failed generation delete must be superseded: skip=%v err=%v", skip, err)
	}
	if skip, _, err := reloaded.beginInboundMutationLocked("remove", &ChildInboundRequest{Tag: tag, MutationID: oldMutationID}); err != nil || skip {
		t.Fatalf("restored generation delete must remain valid: skip=%v err=%v", skip, err)
	}
}
