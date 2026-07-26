package agentfirewall

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

// PortRule is one public host-firewall allowance derived from an Xray inbound.
// Protocol is always "tcp" or "udp".
type PortRule struct {
	Protocol string
	Port     uint16
}

// RulesFromFile reads an Xray JSON config and returns the public listening
// sockets that Arcway must admit through the host firewall.
func RulesFromFile(path string) ([]PortRule, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return RulesFromReader(file)
}

// RulesFromReader parses the structured Xray configuration. It intentionally
// ignores API and loopback-only inbounds so management interfaces are never
// made public as a side effect of synchronization.
func RulesFromReader(reader io.Reader) ([]PortRule, error) {
	decoder := json.NewDecoder(reader)
	decoder.UseNumber()
	var config struct {
		Inbounds []map[string]interface{} `json:"inbounds"`
	}
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("parse Xray config: %w", err)
	}

	unique := make(map[PortRule]struct{})
	for index, inbound := range config.Inbounds {
		if !isPublicInbound(inbound) {
			continue
		}
		port, ok, err := inboundPort(inbound["port"])
		if err != nil {
			return nil, fmt.Errorf("inbound %d: %w", index, err)
		}
		if !ok {
			continue
		}
		for _, protocol := range inboundTransports(inbound) {
			unique[PortRule{Protocol: protocol, Port: port}] = struct{}{}
		}
	}

	rules := make([]PortRule, 0, len(unique))
	for rule := range unique {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Protocol != rules[j].Protocol {
			return rules[i].Protocol < rules[j].Protocol
		}
		return rules[i].Port < rules[j].Port
	})
	return rules, nil
}

func isPublicInbound(inbound map[string]interface{}) bool {
	tag, _ := inbound["tag"].(string)
	if strings.EqualFold(strings.TrimSpace(tag), "api") {
		return false
	}

	listen, _ := inbound["listen"].(string)
	listen = strings.TrimSpace(strings.Trim(listen, "[]"))
	if listen == "" {
		return true
	}
	if strings.EqualFold(listen, "localhost") {
		return false
	}
	ip := net.ParseIP(strings.Split(listen, "%")[0])
	return ip == nil || !ip.IsLoopback()
}

func inboundPort(raw interface{}) (uint16, bool, error) {
	if raw == nil {
		return 0, false, nil
	}
	var value int64
	switch typed := raw.(type) {
	case json.Number:
		parsed, err := strconv.ParseInt(typed.String(), 10, 32)
		if err != nil {
			return 0, false, fmt.Errorf("invalid listening port %q", typed.String())
		}
		value = parsed
	case float64:
		value = int64(typed)
		if float64(value) != typed {
			return 0, false, fmt.Errorf("invalid listening port %v", typed)
		}
	case string:
		parsed, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 32)
		if err != nil {
			return 0, false, fmt.Errorf("unsupported listening port %q", typed)
		}
		value = parsed
	default:
		return 0, false, fmt.Errorf("invalid listening port type %T", raw)
	}
	if value < 1 || value > 65535 {
		return 0, false, fmt.Errorf("listening port %d is outside 1-65535", value)
	}
	return uint16(value), true, nil
}

func inboundTransports(inbound map[string]interface{}) []string {
	protocol := strings.ToLower(strings.TrimSpace(stringValue(inbound["protocol"])))
	settings, _ := inbound["settings"].(map[string]interface{})

	switch protocol {
	case "wireguard":
		return []string{"udp"}
	case "hysteria", "hysteria2", "hy2":
		return []string{"udp"}
	case "dokodemo-door", "tunnel":
		return parseNetworkList(stringValue(settings["network"]), "tcp")
	case "shadowsocks":
		return parseNetworkList(stringValue(settings["network"]), "tcp")
	case "socks", "mixed":
		if enabled, _ := settings["udp"].(bool); enabled {
			return []string{"tcp", "udp"}
		}
	}

	streamSettings, _ := inbound["streamSettings"].(map[string]interface{})
	network := strings.ToLower(strings.TrimSpace(stringValue(streamSettings["network"])))
	switch network {
	case "kcp", "mkcp", "quic", "hysteria", "hysteria2", "hy2":
		return []string{"udp"}
	default:
		// Xray's raw/tcp, WebSocket, HTTP, HTTPUpgrade, gRPC and XHTTP
		// transports all expose a TCP listening socket.
		return []string{"tcp"}
	}
}

func parseNetworkList(value, fallback string) []string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		value = fallback
	}
	seen := make(map[string]bool)
	for _, part := range strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '|' || r == ' ' || r == ';'
	}) {
		if part == "tcp" || part == "udp" {
			seen[part] = true
		}
	}
	result := make([]string, 0, 2)
	if seen["tcp"] {
		result = append(result, "tcp")
	}
	if seen["udp"] {
		result = append(result, "udp")
	}
	if len(result) == 0 {
		return []string{fallback}
	}
	return result
}

func stringValue(value interface{}) string {
	result, _ := value.(string)
	return result
}
