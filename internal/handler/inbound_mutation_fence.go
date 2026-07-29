package handler

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const inboundMutationFenceVersion = 2
const inboundMutationFenceSidecarName = ".relaydock-inbound-mutation-fences.json"

func defaultChildInboundMutationFencePath() string {
	path := filepath.Join("data", inboundMutationFenceSidecarName)
	if absolute, err := filepath.Abs(path); err == nil {
		return absolute
	}
	return filepath.Clean(path)
}

func childInboundMutationLegacySidecars() []string {
	paths := make([]string, 0, len(childXrayConfigPaths))
	for _, configPath := range childXrayConfigPaths {
		paths = append(paths, filepath.Join(filepath.Dir(configPath), inboundMutationFenceSidecarName))
	}
	return paths
}

type inboundMutationFenceState struct {
	Owner    string
	Canceled map[string]struct{}
	Pending  *inboundMutationFencePending
}

// inboundMutationFencePending is the durable write-ahead record for an add.
// Owner remains the last committed generation until the Xray config contains
// the intended inbound and the sidecar commit succeeds.
type inboundMutationFencePending struct {
	Owner                string
	ConfigPath           string
	IntendedDigest       string
	PreviousOwner        string
	PreviousStatePresent bool
	PreviousPresent      bool
	PreviousDigest       string
}

type inboundMutationFenceTransaction struct {
	tag            string
	owner          string
	previous       inboundMutationFenceState
	previousExists bool
	active         bool
}

type inboundMutationFenceFile struct {
	Version int                                    `json:"version"`
	Tags    map[string]inboundMutationFenceFileTag `json:"tags"`
}

type inboundMutationFenceFileTag struct {
	Owner    string                           `json:"owner,omitempty"`
	Canceled []string                         `json:"canceled,omitempty"`
	Pending  *inboundMutationFenceFilePending `json:"pending,omitempty"`
}

type inboundMutationFenceFilePending struct {
	Owner                string `json:"owner"`
	ConfigPath           string `json:"config_path"`
	IntendedDigest       string `json:"intended_digest"`
	PreviousOwner        string `json:"previous_owner,omitempty"`
	PreviousStatePresent bool   `json:"previous_state_present"`
	PreviousPresent      bool   `json:"previous_inbound_present"`
	PreviousDigest       string `json:"previous_digest,omitempty"`
}

// beginInboundMutationLocked records remove tombstones before touching Xray.
// Add callers normally use beginInboundAddMutationLocked so the previous
// config and WAL digest come from the same serialized transaction.
func (h *ChildManageHandler) beginInboundMutationLocked(action string, req *ChildInboundRequest) (bool, *inboundMutationFenceTransaction, error) {
	mutationID := strings.TrimSpace(req.MutationID)
	switch action {
	case "add":
		if req.Inbound == nil {
			return false, nil, nil
		}
		tag, _ := req.Inbound["tag"].(string)
		tag = strings.TrimSpace(tag)
		configPath := h.findXrayConfigPath()
		var previous map[string]interface{}
		if configPath != "" && tag != "" {
			var err error
			previous, err = inboundMutationFromConfig(configPath, tag)
			if err != nil {
				return false, nil, err
			}
		}
		transaction, err := h.beginInboundAddMutationLocked(req, configPath, previous)
		return false, transaction, err

	case "remove":
		req.Tag = strings.TrimSpace(req.Tag)
		if req.Tag == "" {
			return false, nil, nil
		}
		if err := h.ensureInboundMutationFencesLocked(); err != nil {
			return false, nil, err
		}
		previous := cloneInboundMutationFenceState(h.inboundMutationFences[req.Tag])
		state := cloneInboundMutationFenceState(previous)
		if state.Canceled == nil {
			state.Canceled = make(map[string]struct{})
		}
		if mutationID == "" {
			if state.Owner != "" {
				return false, nil, fmt.Errorf("mutation_id is required to remove owned inbound %s", req.Tag)
			}
			return false, nil, nil
		}
		state.Canceled[mutationID] = struct{}{}
		candidate := cloneInboundMutationFenceStates(h.inboundMutationFences)
		candidate[req.Tag] = state
		if err := h.persistInboundMutationFenceStatesLocked(candidate); err != nil {
			if atomicRenameWasApplied(err) {
				h.inboundMutationFences = candidate
			}
			return false, nil, err
		}
		h.inboundMutationFences = candidate
		return state.Owner != "" && state.Owner != mutationID, nil, nil
	}
	return false, nil, nil
}

// beginInboundAddMutationLocked persists pending before any runtime or config
// side effect. configPath and previousInbound must describe the config snapshot
// the caller will restore if the operation fails.
func (h *ChildManageHandler) beginInboundAddMutationLocked(
	req *ChildInboundRequest,
	configPath string,
	previousInbound map[string]interface{},
) (*inboundMutationFenceTransaction, error) {
	if req.Inbound == nil {
		return nil, nil
	}
	tag, _ := req.Inbound["tag"].(string)
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return nil, nil
	}
	if err := h.ensureInboundMutationFencesLocked(); err != nil {
		return nil, err
	}

	mutationID := strings.TrimSpace(req.MutationID)
	previous, previousExists := h.inboundMutationFences[tag]
	previous = cloneInboundMutationFenceState(previous)
	if previous.Pending != nil {
		return nil, fmt.Errorf("inbound mutation recovery is still pending for %s", tag)
	}
	if mutationID == "" {
		if previous.Owner != "" || len(previous.Canceled) > 0 {
			return nil, fmt.Errorf("mutation_id is required to replace fenced inbound %s", tag)
		}
		return nil, nil
	}
	if _, canceled := previous.Canceled[mutationID]; canceled {
		return nil, fmt.Errorf("inbound mutation %s for %s was canceled", mutationID, tag)
	}

	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return nil, fmt.Errorf("Xray config path is required to fence inbound %s", tag)
	}
	if absolute, err := filepath.Abs(configPath); err == nil {
		configPath = absolute
	} else {
		configPath = filepath.Clean(configPath)
	}
	intendedDigest, err := canonicalInboundMutationDigest(req.Inbound)
	if err != nil {
		return nil, fmt.Errorf("digest intended inbound %s: %w", tag, err)
	}
	previousDigest, err := canonicalInboundMutationDigest(previousInbound)
	if err != nil {
		return nil, fmt.Errorf("digest previous inbound %s: %w", tag, err)
	}

	state := cloneInboundMutationFenceState(previous)
	if state.Canceled == nil {
		state.Canceled = make(map[string]struct{})
	}
	state.Pending = &inboundMutationFencePending{
		Owner:                mutationID,
		ConfigPath:           configPath,
		IntendedDigest:       intendedDigest,
		PreviousOwner:        previous.Owner,
		PreviousStatePresent: previousExists,
		PreviousPresent:      previousInbound != nil,
		PreviousDigest:       previousDigest,
	}
	if err := h.validatePendingInboundMutationConfigPath(tag, state.Pending); err != nil {
		return nil, err
	}
	candidate := cloneInboundMutationFenceStates(h.inboundMutationFences)
	candidate[tag] = state
	if err := h.persistInboundMutationFenceStatesLocked(candidate); err != nil {
		if atomicRenameWasApplied(err) {
			h.inboundMutationFences = candidate
			rollbackCandidate := cloneInboundMutationFenceStates(candidate)
			if previousExists {
				rollbackCandidate[tag] = cloneInboundMutationFenceState(previous)
			} else {
				delete(rollbackCandidate, tag)
			}
			rollbackErr := h.persistInboundMutationFenceStatesLocked(rollbackCandidate)
			if rollbackErr == nil || atomicRenameWasApplied(rollbackErr) {
				h.inboundMutationFences = rollbackCandidate
			}
			if rollbackErr != nil {
				return nil, errors.Join(err, fmt.Errorf("restore inbound mutation fence after reservation failure: %w", rollbackErr))
			}
		}
		return nil, err
	}
	h.inboundMutationFences = candidate
	return &inboundMutationFenceTransaction{
		tag:            tag,
		owner:          mutationID,
		previous:       previous,
		previousExists: previousExists,
		active:         true,
	}, nil
}

func (transaction *inboundMutationFenceTransaction) abandonForRecovery() {
	if transaction != nil {
		transaction.active = false
	}
}

func (h *ChildManageHandler) commitInboundMutationLocked(transaction *inboundMutationFenceTransaction) error {
	if transaction == nil || !transaction.active {
		return nil
	}
	state, exists := h.inboundMutationFences[transaction.tag]
	if !exists || state.Pending == nil || state.Pending.Owner != transaction.owner {
		transaction.active = false
		return fmt.Errorf("pending inbound mutation %s for %s was lost", transaction.owner, transaction.tag)
	}
	if err := h.validatePendingInboundMutationConfigPath(transaction.tag, state.Pending); err != nil {
		transaction.active = false
		return err
	}
	actualDigest, actualPresent, err := inboundMutationDigestFromConfig(state.Pending.ConfigPath, transaction.tag)
	if err != nil {
		transaction.active = false
		return fmt.Errorf("verify committed inbound mutation %s for %s: %w", transaction.owner, transaction.tag, err)
	}
	if !actualPresent || actualDigest != state.Pending.IntendedDigest {
		transaction.active = false
		return fmt.Errorf("durable Xray config does not contain intended inbound mutation %s for %s", transaction.owner, transaction.tag)
	}
	candidate := cloneInboundMutationFenceStates(h.inboundMutationFences)
	candidateState := cloneInboundMutationFenceState(state)
	candidateState.Owner = transaction.owner
	candidateState.Pending = nil
	candidate[transaction.tag] = candidateState
	err = h.persistInboundMutationFenceStatesLocked(candidate)
	if err == nil || atomicRenameWasApplied(err) {
		h.inboundMutationFences = candidate
	}
	// Config already contains intended. Never let deferred rollback claim the
	// previous generation if the final sidecar write is uncertain.
	transaction.active = false
	return err
}

func (h *ChildManageHandler) rollbackInboundMutationLocked(transaction *inboundMutationFenceTransaction) error {
	if transaction == nil || !transaction.active {
		return nil
	}
	candidate := cloneInboundMutationFenceStates(h.inboundMutationFences)
	if transaction.previousExists {
		candidate[transaction.tag] = cloneInboundMutationFenceState(transaction.previous)
	} else {
		delete(candidate, transaction.tag)
	}
	err := h.persistInboundMutationFenceStatesLocked(candidate)
	if err == nil || atomicRenameWasApplied(err) {
		h.inboundMutationFences = candidate
	}
	transaction.active = false
	if err != nil {
		return fmt.Errorf("restore inbound mutation fence for %s: %w", transaction.tag, err)
	}
	return nil
}

func cloneInboundMutationFenceState(state inboundMutationFenceState) inboundMutationFenceState {
	cloned := inboundMutationFenceState{Owner: state.Owner}
	if state.Canceled != nil {
		cloned.Canceled = make(map[string]struct{}, len(state.Canceled))
		for mutationID := range state.Canceled {
			cloned.Canceled[mutationID] = struct{}{}
		}
	}
	if state.Pending != nil {
		pending := *state.Pending
		cloned.Pending = &pending
	}
	return cloned
}

func cloneInboundMutationFenceStates(states map[string]inboundMutationFenceState) map[string]inboundMutationFenceState {
	cloned := make(map[string]inboundMutationFenceState, len(states))
	for tag, state := range states {
		cloned[tag] = cloneInboundMutationFenceState(state)
	}
	return cloned
}

// completeInboundMutationRemovalLocked keeps the cancellation tombstone but
// clears ownership only after runtime and config removal both completed.
func (h *ChildManageHandler) completeInboundMutationRemovalLocked(tag, mutationID string) error {
	tag = strings.TrimSpace(tag)
	mutationID = strings.TrimSpace(mutationID)
	if tag == "" || !h.inboundMutationFencesLoaded {
		return nil
	}
	state, ok := h.inboundMutationFences[tag]
	if !ok {
		return nil
	}
	if mutationID == "" || state.Owner == mutationID {
		if state.Owner == "" {
			return nil
		}
		candidate := cloneInboundMutationFenceStates(h.inboundMutationFences)
		candidateState := cloneInboundMutationFenceState(state)
		candidateState.Owner = ""
		candidate[tag] = candidateState
		if err := h.persistInboundMutationFenceStatesLocked(candidate); err != nil {
			if atomicRenameWasApplied(err) {
				h.inboundMutationFences = candidate
			}
			return err
		}
		h.inboundMutationFences = candidate
	}
	return nil
}

func (h *ChildManageHandler) ensureInboundMutationFencesLocked() error {
	if err := h.loadInboundMutationFencesLocked(); err != nil {
		return err
	}
	for tag, state := range h.inboundMutationFences {
		if state.Pending != nil {
			return fmt.Errorf("inbound mutation recovery is pending for %s", tag)
		}
	}
	return nil
}

func (h *ChildManageHandler) loadInboundMutationFencesLocked() error {
	path := h.inboundMutationFencePath
	if path == "" {
		path = defaultChildInboundMutationFencePath()
		if h.inboundMutationLegacyPaths == nil {
			h.inboundMutationLegacyPaths = childInboundMutationLegacySidecars()
		}
	}
	if absolute, err := filepath.Abs(path); err == nil {
		path = absolute
	} else {
		path = filepath.Clean(path)
	}
	if h.inboundMutationFencesLoaded && h.inboundMutationFencePath == path {
		return nil
	}

	states, _, version, err := readInboundMutationFenceStates(path)
	if err != nil {
		return err
	}
	origins := make(map[string]string, len(states))
	for tag := range states {
		origins[tag] = path
	}
	legacyFiles := make([]string, 0, len(h.inboundMutationLegacyPaths))
	seenLegacy := map[string]struct{}{filepath.Clean(path): {}}
	for _, legacyPath := range h.inboundMutationLegacyPaths {
		legacyPath = strings.TrimSpace(legacyPath)
		if legacyPath == "" {
			continue
		}
		if absolute, absoluteErr := filepath.Abs(legacyPath); absoluteErr == nil {
			legacyPath = absolute
		} else {
			legacyPath = filepath.Clean(legacyPath)
		}
		if _, duplicate := seenLegacy[legacyPath]; duplicate {
			continue
		}
		seenLegacy[legacyPath] = struct{}{}
		legacyStates, exists, _, readErr := readInboundMutationFenceStates(legacyPath)
		if readErr != nil {
			return readErr
		}
		if !exists {
			continue
		}
		if err := mergeInboundMutationFenceStates(states, origins, legacyStates, legacyPath); err != nil {
			return err
		}
		legacyFiles = append(legacyFiles, legacyPath)
	}
	h.inboundMutationFencePath = path
	h.inboundMutationFences = states
	h.inboundMutationFencesLoaded = true
	if version == 1 || len(legacyFiles) > 0 {
		// Version 1 entries are already committed owner/tombstone records. Rewrite
		// them as v2 and merge every config-adjacent legacy sidecar before deleting
		// any source file. A config-path priority change can then never reset owner.
		if err := h.persistInboundMutationFenceStatesLocked(states); err != nil {
			h.inboundMutationFencesLoaded = false
			return fmt.Errorf("migrate inbound mutation fence to stable state path: %w", err)
		}
		for _, legacyPath := range legacyFiles {
			if err := os.Remove(legacyPath); err != nil && !os.IsNotExist(err) {
				h.inboundMutationFencesLoaded = false
				return fmt.Errorf("remove migrated inbound mutation fence %s: %w", legacyPath, err)
			}
			if err := syncRenamedFileDirectory(legacyPath); err != nil {
				h.inboundMutationFencesLoaded = false
				return fmt.Errorf("sync migrated inbound mutation fence directory %s: %w", filepath.Dir(legacyPath), err)
			}
		}
	}
	return nil
}

type inboundMutationRuntimeConverger func(configPath, tag string, inbound map[string]interface{}, present bool) error

func (h *ChildManageHandler) resolvePendingInboundMutationsLocked(converge inboundMutationRuntimeConverger) error {
	if err := h.loadInboundMutationFencesLocked(); err != nil {
		return err
	}
	candidate := cloneInboundMutationFenceStates(h.inboundMutationFences)
	changed := false
	tags := make([]string, 0, len(candidate))
	for tag, state := range candidate {
		if state.Pending != nil {
			tags = append(tags, tag)
		}
	}
	sort.Strings(tags)
	for _, tag := range tags {
		state := candidate[tag]
		pending := state.Pending
		if pending == nil {
			continue
		}
		if pending.PreviousOwner != state.Owner {
			return fmt.Errorf("inbound mutation WAL owner mismatch for tag %q", tag)
		}
		if err := h.validatePendingInboundMutationConfigPath(tag, pending); err != nil {
			return err
		}
		actualInbound, err := inboundMutationFromConfig(pending.ConfigPath, tag)
		if errors.Is(err, os.ErrNotExist) {
			actualInbound = nil
			err = nil
		}
		if err != nil {
			return fmt.Errorf("recover pending inbound mutation for %s: %w", tag, err)
		}
		actualPresent := actualInbound != nil
		actualDigest, err := canonicalInboundMutationDigest(actualInbound)
		if err != nil {
			return fmt.Errorf("digest durable inbound during recovery for %s: %w", tag, err)
		}
		matchesIntended := actualPresent && actualDigest == pending.IntendedDigest
		matchesPrevious := actualPresent == pending.PreviousPresent && (!actualPresent || actualDigest == pending.PreviousDigest)
		if !matchesIntended && !matchesPrevious {
			return fmt.Errorf("pending inbound mutation for %s does not match intended or previous durable config", tag)
		}
		if converge == nil {
			return fmt.Errorf("runtime convergence is required to recover pending inbound mutation for %s", tag)
		}
		if err := converge(pending.ConfigPath, tag, actualInbound, actualPresent); err != nil {
			return fmt.Errorf("converge Xray runtime for pending inbound mutation %s: %w", tag, err)
		}
		switch {
		case matchesIntended:
			state.Owner = pending.Owner
			state.Pending = nil
			candidate[tag] = state
			changed = true
		case matchesPrevious:
			state.Owner = pending.PreviousOwner
			state.Pending = nil
			if !pending.PreviousStatePresent && state.Owner == "" && len(state.Canceled) == 0 {
				delete(candidate, tag)
			} else {
				candidate[tag] = state
			}
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := h.persistInboundMutationFenceStatesLocked(candidate); err != nil {
		if atomicRenameWasApplied(err) {
			h.inboundMutationFences = candidate
		}
		return fmt.Errorf("persist recovered inbound mutation ownership: %w", err)
	}
	h.inboundMutationFences = candidate
	return nil
}

func (h *ChildManageHandler) validatePendingInboundMutationConfigPath(tag string, pending *inboundMutationFencePending) error {
	if pending == nil || h.inboundMutationActiveConfig == nil {
		return nil
	}
	activePath := strings.TrimSpace(h.inboundMutationActiveConfig())
	if activePath == "" {
		return fmt.Errorf("cannot recover pending inbound mutation for %s without an active Xray config", tag)
	}
	if absolute, err := filepath.Abs(activePath); err == nil {
		activePath = absolute
	} else {
		activePath = filepath.Clean(activePath)
	}
	pendingPath := strings.TrimSpace(pending.ConfigPath)
	if absolute, err := filepath.Abs(pendingPath); err == nil {
		pendingPath = absolute
	} else {
		pendingPath = filepath.Clean(pendingPath)
	}
	if pendingPath != activePath {
		return fmt.Errorf("pending inbound mutation for %s belongs to inactive Xray config %s (active %s)", tag, pendingPath, activePath)
	}
	return nil
}

func inboundMutationFromConfig(configPath, tag string) (map[string]interface{}, error) {
	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return nil, fmt.Errorf("Xray config path is required")
	}
	content, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read Xray config %s: %w", configPath, err)
	}
	var config map[string]interface{}
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.UseNumber()
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("parse Xray config %s: %w", configPath, err)
	}
	rawInbounds, _ := config["inbounds"].([]interface{})
	var found map[string]interface{}
	for _, raw := range rawInbounds {
		inbound, _ := raw.(map[string]interface{})
		inboundTag, _ := inbound["tag"].(string)
		if strings.TrimSpace(inboundTag) != strings.TrimSpace(tag) {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("Xray config %s contains duplicate inbound tag %q", configPath, tag)
		}
		found = inbound
	}
	return found, nil
}

func inboundMutationDigestFromConfig(configPath, tag string) (string, bool, error) {
	inbound, err := inboundMutationFromConfig(configPath, tag)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if inbound == nil {
		return "", false, nil
	}
	digest, err := canonicalInboundMutationDigest(inbound)
	return digest, true, err
}

func canonicalInboundMutationDigest(inbound map[string]interface{}) (string, error) {
	if inbound == nil {
		return "", nil
	}
	content, err := json.Marshal(inbound)
	if err != nil {
		return "", err
	}
	var canonical interface{}
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.UseNumber()
	if err := decoder.Decode(&canonical); err != nil {
		return "", err
	}
	content, err = json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(content)
	return fmt.Sprintf("%x", digest[:]), nil
}

func readInboundMutationFenceStates(path string) (map[string]inboundMutationFenceState, bool, int, error) {
	states := make(map[string]inboundMutationFenceState)
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return states, false, inboundMutationFenceVersion, nil
	}
	if err != nil {
		return nil, false, 0, fmt.Errorf("read inbound mutation fence %s: %w", path, err)
	}
	var file inboundMutationFenceFile
	if err := json.Unmarshal(content, &file); err != nil {
		return nil, false, 0, fmt.Errorf("parse inbound mutation fence %s: %w", path, err)
	}
	if file.Version != 1 && file.Version != inboundMutationFenceVersion {
		return nil, false, 0, fmt.Errorf("unsupported inbound mutation fence version %d in %s", file.Version, path)
	}
	for rawTag, entry := range file.Tags {
		tag := strings.TrimSpace(rawTag)
		if tag == "" {
			continue
		}
		state := inboundMutationFenceState{
			Owner:    strings.TrimSpace(entry.Owner),
			Canceled: make(map[string]struct{}, len(entry.Canceled)),
		}
		for _, mutationID := range entry.Canceled {
			if mutationID = strings.TrimSpace(mutationID); mutationID != "" {
				state.Canceled[mutationID] = struct{}{}
			}
		}
		if entry.Pending != nil {
			if file.Version == 1 {
				return nil, false, 0, fmt.Errorf("v1 inbound mutation fence contains pending state for tag %q in %s", tag, path)
			}
			pending := &inboundMutationFencePending{
				Owner:                strings.TrimSpace(entry.Pending.Owner),
				ConfigPath:           strings.TrimSpace(entry.Pending.ConfigPath),
				IntendedDigest:       strings.TrimSpace(entry.Pending.IntendedDigest),
				PreviousOwner:        strings.TrimSpace(entry.Pending.PreviousOwner),
				PreviousStatePresent: entry.Pending.PreviousStatePresent,
				PreviousPresent:      entry.Pending.PreviousPresent,
				PreviousDigest:       strings.TrimSpace(entry.Pending.PreviousDigest),
			}
			if pending.Owner == "" || pending.ConfigPath == "" || pending.IntendedDigest == "" {
				return nil, false, 0, fmt.Errorf("invalid pending inbound mutation for tag %q in %s", tag, path)
			}
			if pending.PreviousPresent && pending.PreviousDigest == "" {
				return nil, false, 0, fmt.Errorf("pending inbound mutation for tag %q has no previous digest in %s", tag, path)
			}
			if pending.PreviousOwner != state.Owner {
				return nil, false, 0, fmt.Errorf("pending inbound mutation owner mismatch for tag %q in %s", tag, path)
			}
			state.Pending = pending
		}
		if state.Owner != "" || len(state.Canceled) > 0 || state.Pending != nil {
			states[tag] = state
		}
	}
	return states, true, file.Version, nil
}

func mergeInboundMutationFenceStates(
	destination map[string]inboundMutationFenceState,
	origins map[string]string,
	source map[string]inboundMutationFenceState,
	sourcePath string,
) error {
	for tag, incoming := range source {
		existing, exists := destination[tag]
		if !exists {
			destination[tag] = cloneInboundMutationFenceState(incoming)
			origins[tag] = sourcePath
			continue
		}
		if strings.TrimSpace(existing.Owner) != strings.TrimSpace(incoming.Owner) {
			return fmt.Errorf("inbound mutation owner conflict for tag %q between %s and %s", tag, origins[tag], sourcePath)
		}
		if !equalInboundMutationFencePending(existing.Pending, incoming.Pending) {
			return fmt.Errorf("pending inbound mutation conflict for tag %q between %s and %s", tag, origins[tag], sourcePath)
		}
		if existing.Canceled == nil {
			existing.Canceled = make(map[string]struct{})
		}
		for mutationID := range incoming.Canceled {
			existing.Canceled[mutationID] = struct{}{}
		}
		destination[tag] = existing
	}
	return nil
}

func equalInboundMutationFencePending(left, right *inboundMutationFencePending) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func (h *ChildManageHandler) persistInboundMutationFenceStatesLocked(states map[string]inboundMutationFenceState) error {
	if !h.inboundMutationFencesLoaded || h.inboundMutationFencePath == "" {
		return fmt.Errorf("inbound mutation fence is not loaded")
	}
	if err := os.MkdirAll(filepath.Dir(h.inboundMutationFencePath), 0700); err != nil {
		return fmt.Errorf("create inbound mutation fence state directory: %w", err)
	}
	file := inboundMutationFenceFileFromStates(states)
	writer := h.inboundMutationFenceWriter
	if writer == nil {
		writer = writeJSONFileAtomic
	}
	if err := writer(h.inboundMutationFencePath, file); err != nil {
		return fmt.Errorf("write inbound mutation fence: %w", err)
	}
	return nil
}

func inboundMutationFenceFileFromStates(states map[string]inboundMutationFenceState) inboundMutationFenceFile {
	file := inboundMutationFenceFile{Version: inboundMutationFenceVersion, Tags: make(map[string]inboundMutationFenceFileTag, len(states))}
	for tag, state := range states {
		entry := inboundMutationFenceFileTag{Owner: state.Owner}
		for mutationID := range state.Canceled {
			entry.Canceled = append(entry.Canceled, mutationID)
		}
		sort.Strings(entry.Canceled)
		if state.Pending != nil {
			entry.Pending = &inboundMutationFenceFilePending{
				Owner:                state.Pending.Owner,
				ConfigPath:           state.Pending.ConfigPath,
				IntendedDigest:       state.Pending.IntendedDigest,
				PreviousOwner:        state.Pending.PreviousOwner,
				PreviousStatePresent: state.Pending.PreviousStatePresent,
				PreviousPresent:      state.Pending.PreviousPresent,
				PreviousDigest:       state.Pending.PreviousDigest,
			}
		}
		if entry.Owner != "" || len(entry.Canceled) > 0 || entry.Pending != nil {
			file.Tags[tag] = entry
		}
	}
	return file
}
