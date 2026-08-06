package handler

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"github.com/violetaini/relaydock/internal/storage"
)

func isTunnelProtocol(protocol string) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "tunnel", "dokodemo-door":
		return true
	default:
		return false
	}
}

func toInt(value any) int {
	switch number := value.(type) {
	case float64:
		return int(number)
	case int:
		return number
	case int64:
		return int(number)
	default:
		return 0
	}
}

// serverEntryHost returns the public address used by managed forwarding.
func serverEntryHost(server *storage.RemoteServer) string {
	if server == nil {
		return ""
	}
	for _, value := range []string{server.IPAddress, server.Domain, server.PullAddress} {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	if server.IPv6Enabled {
		return strings.TrimSpace(server.IPAddressV6)
	}
	return ""
}

func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": err.Error(),
	})
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// writeJSON 写一份成功响应(任意结构)。
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func sortNodesByNodeOrder(nodes []storage.Node, nodeOrder []int64) {
	if len(nodeOrder) == 0 || len(nodes) == 0 {
		return
	}

	nodeIDToPosition := make(map[int64]int, len(nodeOrder))
	for pos, nodeID := range nodeOrder {
		nodeIDToPosition[nodeID] = pos
	}

	sort.SliceStable(nodes, func(i, j int) bool {
		posI, foundI := nodeIDToPosition[nodes[i].ID]
		posJ, foundJ := nodeIDToPosition[nodes[j].ID]

		if !foundI {
			return false
		}
		if !foundJ {
			return true
		}
		return posI < posJ
	})
}
