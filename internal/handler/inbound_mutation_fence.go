package handler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const inboundMutationFenceVersion = 1
const inboundMutationFenceSidecarName = ".mmwx-inbound-mutation-fences.json"
const unfencedInboundMutationOwner = "-"

type inboundMutationFenceState struct {
	Owner    string
	Canceled map[string]struct{}
}

type inboundMutationFenceFile struct {
	Version int                                    `json:"version"`
	Tags    map[string]inboundMutationFenceFileTag `json:"tags"`
}

type inboundMutationFenceFileTag struct {
	Owner    string   `json:"owner,omitempty"`
	Canceled []string `json:"canceled,omitempty"`
}

// beginInboundMutationLocked records a cancellation before a remove can touch
// Xray. A delayed add with the same mutation ID is then rejected even when the
// remove reached the Agent first. Callers must hold inboundsMu.
func (h *ChildManageHandler) beginInboundMutationLocked(action string, req *ChildInboundRequest) (bool, error) {
	mutationID := strings.TrimSpace(req.MutationID)
	switch action {
	case "add":
		if req.Inbound == nil {
			return false, nil
		}
		tag, _ := req.Inbound["tag"].(string)
		tag = strings.TrimSpace(tag)
		if tag == "" {
			return false, nil
		}
		if err := h.ensureInboundMutationFencesLocked(); err != nil {
			return false, err
		}
		state := h.inboundMutationFence(tag)
		if mutationID != "" {
			if _, canceled := state.Canceled[mutationID]; canceled {
				return false, fmt.Errorf("inbound mutation %s for %s was canceled", mutationID, tag)
			}
			state.Owner = mutationID
		} else if state.Owner != "" || len(state.Canceled) > 0 {
			// A normal add can supersede an old fenced mutation. Keep the old
			// tombstone, but prevent its delayed remove from deleting this inbound.
			state.Owner = unfencedInboundMutationOwner
		}
		if mutationID != "" || state.Owner != "" {
			h.inboundMutationFences[tag] = state
			if err := h.persistInboundMutationFencesLocked(); err != nil {
				return false, err
			}
		}
		return false, nil

	case "remove":
		if mutationID == "" {
			return false, nil
		}
		req.Tag = strings.TrimSpace(req.Tag)
		if req.Tag == "" {
			return false, nil
		}
		if err := h.ensureInboundMutationFencesLocked(); err != nil {
			return false, err
		}
		state := h.inboundMutationFence(req.Tag)
		state.Canceled[mutationID] = struct{}{}
		h.inboundMutationFences[req.Tag] = state
		if err := h.persistInboundMutationFencesLocked(); err != nil {
			return false, err
		}
		return state.Owner != "" && state.Owner != mutationID, nil
	}
	return false, nil
}

// completeInboundMutationRemovalLocked keeps the cancellation tombstone but
// clears ownership only after runtime and disk removal both completed.
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
		state.Owner = ""
		h.inboundMutationFences[tag] = state
		return h.persistInboundMutationFencesLocked()
	}
	return nil
}

func (h *ChildManageHandler) inboundMutationFence(tag string) inboundMutationFenceState {
	state := h.inboundMutationFences[tag]
	if state.Canceled == nil {
		state.Canceled = make(map[string]struct{})
	}
	h.inboundMutationFences[tag] = state
	return state
}

func (h *ChildManageHandler) ensureInboundMutationFencesLocked() error {
	path := h.inboundMutationFencePath
	if path == "" {
		configPath := h.findXrayConfigPath()
		if configPath == "" {
			return fmt.Errorf("Xray config not found for inbound mutation fence")
		}
		path = filepath.Join(filepath.Dir(configPath), inboundMutationFenceSidecarName)
	}
	if h.inboundMutationFencesLoaded && h.inboundMutationFencePath == path {
		return nil
	}

	states := make(map[string]inboundMutationFenceState)
	content, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read inbound mutation fence: %w", err)
	}
	if err == nil {
		var file inboundMutationFenceFile
		if err := json.Unmarshal(content, &file); err != nil {
			return fmt.Errorf("parse inbound mutation fence: %w", err)
		}
		if file.Version != inboundMutationFenceVersion {
			return fmt.Errorf("unsupported inbound mutation fence version %d", file.Version)
		}
		for tag, entry := range file.Tags {
			tag = strings.TrimSpace(tag)
			if tag == "" {
				continue
			}
			state := inboundMutationFenceState{Owner: entry.Owner, Canceled: make(map[string]struct{}, len(entry.Canceled))}
			for _, mutationID := range entry.Canceled {
				if mutationID = strings.TrimSpace(mutationID); mutationID != "" {
					state.Canceled[mutationID] = struct{}{}
				}
			}
			states[tag] = state
		}
	}
	h.inboundMutationFencePath = path
	h.inboundMutationFences = states
	h.inboundMutationFencesLoaded = true
	return nil
}

func (h *ChildManageHandler) persistInboundMutationFencesLocked() error {
	if !h.inboundMutationFencesLoaded || h.inboundMutationFencePath == "" {
		return fmt.Errorf("inbound mutation fence is not loaded")
	}
	file := inboundMutationFenceFile{Version: inboundMutationFenceVersion, Tags: make(map[string]inboundMutationFenceFileTag, len(h.inboundMutationFences))}
	for tag, state := range h.inboundMutationFences {
		entry := inboundMutationFenceFileTag{Owner: state.Owner}
		for mutationID := range state.Canceled {
			entry.Canceled = append(entry.Canceled, mutationID)
		}
		sort.Strings(entry.Canceled)
		if entry.Owner != "" || len(entry.Canceled) > 0 {
			file.Tags[tag] = entry
		}
	}
	if err := writeJSONFileAtomic(h.inboundMutationFencePath, file); err != nil {
		return fmt.Errorf("write inbound mutation fence: %w", err)
	}
	return nil
}
