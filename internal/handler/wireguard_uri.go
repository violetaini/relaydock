package handler

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// encodeCanonicalWireGuardURI emits the WireGuard URI form accepted by the
// shared parser without relying on URIProducer's lossy slice formatting.
func encodeCanonicalWireGuardURI(proxy map[string]any) (string, error) {
	server := strings.TrimSpace(wireGuardURIString(proxy["server"]))
	server = strings.TrimSuffix(strings.TrimPrefix(server, "["), "]")
	if server == "" || strings.ContainsAny(server, "/@?#") {
		return "", errors.New("WireGuard server is invalid")
	}
	port, ok := wireGuardURIInt(proxy["port"])
	if !ok || port < 1 || port > 65535 {
		return "", errors.New("WireGuard port is invalid")
	}
	privateKey := strings.TrimSpace(wireGuardURIString(proxy["private-key"]))
	if privateKey == "" {
		return "", errors.New("WireGuard private key is missing")
	}

	params := url.Values{}
	if publicKey := strings.TrimSpace(wireGuardURIString(proxy["public-key"])); publicKey != "" {
		params.Set("publickey", publicKey)
	}
	if addresses := canonicalWireGuardAddresses(proxy); len(addresses) > 0 {
		params.Set("address", strings.Join(addresses, ","))
	}
	if allowedIPs := wireGuardURIList(proxy["allowed-ips"]); len(allowedIPs) > 0 {
		// The shared parser recognizes a bracketed, comma-separated value as an
		// array. url.Values then percent-encodes the commas instead of collapsing
		// []string into the ambiguous "[a b]" representation.
		params.Set("allowed-ips", "["+strings.Join(allowedIPs, ",")+"]")
	}

	for key, value := range proxy {
		switch key {
		case "name", "type", "server", "port", "private-key", "public-key", "ip", "ipv6", "address", "allowed-ips":
			continue
		}
		if strings.HasPrefix(key, "_") || value == nil {
			continue
		}
		if key == "udp" {
			if enabled, valid := wireGuardURIBool(value); valid {
				if enabled {
					params.Set(key, "1")
				} else {
					params.Set(key, "0")
				}
			}
			continue
		}
		if values := wireGuardURIListValue(value); len(values) > 0 {
			params.Set(key, strings.Join(values, ","))
			continue
		}
		if scalar, valid := wireGuardURIScalar(value); valid && scalar != "" {
			params.Set(key, scalar)
		}
	}

	name := strings.TrimSpace(wireGuardURIString(proxy["name"]))
	hostPort := net.JoinHostPort(server, strconv.Itoa(port))
	uri := "wireguard://" + wireGuardURIComponent(privateKey) + "@" + hostPort + "/"
	if query := params.Encode(); query != "" {
		uri += "?" + query
	}
	if name != "" {
		uri += "#" + wireGuardURIComponent(name)
	}
	return uri, nil
}

func canonicalWireGuardAddresses(proxy map[string]any) []string {
	if addresses := wireGuardURIList(proxy["address"]); len(addresses) > 0 {
		return addresses
	}
	addresses := make([]string, 0, 2)
	if value := canonicalWireGuardAddress(wireGuardURIString(proxy["ip"]), 32); value != "" {
		addresses = append(addresses, value)
	}
	if value := canonicalWireGuardAddress(wireGuardURIString(proxy["ipv6"]), 128); value != "" {
		addresses = append(addresses, value)
	}
	return addresses
}

func canonicalWireGuardAddress(value string, hostPrefix int) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.Contains(value, "/") {
		return value
	}
	value = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
	return value + "/" + strconv.Itoa(hostPrefix)
}

func wireGuardURIComponent(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

func wireGuardURIString(value any) string {
	result, _ := value.(string)
	return result
}

func wireGuardURIList(value any) []string {
	if raw, ok := value.(string); ok {
		raw = strings.TrimSpace(raw)
		raw = strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]")
		if raw == "" {
			return nil
		}
		parts := strings.Split(raw, ",")
		result := make([]string, 0, len(parts))
		for _, part := range parts {
			if part = strings.TrimSpace(part); part != "" {
				result = append(result, part)
			}
		}
		return result
	}
	return wireGuardURIListValue(value)
}

func wireGuardURIListValue(value any) []string {
	var values []any
	switch current := value.(type) {
	case []string:
		values = make([]any, len(current))
		for index := range current {
			values[index] = current[index]
		}
	case []any:
		values = current
	default:
		return nil
	}
	result := make([]string, 0, len(values))
	for _, item := range values {
		if scalar, valid := wireGuardURIScalar(item); valid {
			if scalar = strings.TrimSpace(scalar); scalar != "" {
				result = append(result, scalar)
			}
		}
	}
	return result
}

func wireGuardURIScalar(value any) (string, bool) {
	switch current := value.(type) {
	case string:
		return current, true
	case bool:
		return strconv.FormatBool(current), true
	case int:
		return strconv.Itoa(current), true
	case int64:
		return strconv.FormatInt(current, 10), true
	case float64:
		return strconv.FormatFloat(current, 'f', -1, 64), true
	case json.Number:
		return current.String(), true
	default:
		return "", false
	}
}

func wireGuardURIInt(value any) (int, bool) {
	scalar, ok := wireGuardURIScalar(value)
	if !ok {
		return 0, false
	}
	parsed, err := strconv.Atoi(scalar)
	return parsed, err == nil
}

func wireGuardURIBool(value any) (bool, bool) {
	switch current := value.(type) {
	case bool:
		return current, true
	case string:
		switch strings.ToLower(strings.TrimSpace(current)) {
		case "1", "true", "yes", "on":
			return true, true
		case "0", "false", "no", "off":
			return false, true
		}
	case int:
		return current != 0, true
	case int64:
		return current != 0, true
	case float64:
		return current != 0, true
	}
	return false, false
}
