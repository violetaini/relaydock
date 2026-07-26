package handler

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// validateInboundWireGuard protects the panel-managed WireGuard contract before
// the request reaches an Agent. In particular, client private keys belong only
// in the one-time client config and must never be persisted in Xray's config.
func validateInboundWireGuard(inboundReq map[string]interface{}) string {
	inbound, _ := inboundReq["inbound"].(map[string]interface{})
	if inbound == nil || !strings.EqualFold(strings.TrimSpace(wireGuardStringValue(inbound["protocol"])), "wireguard") {
		return ""
	}
	if stream, ok := inbound["streamSettings"].(map[string]interface{}); ok && len(stream) > 0 {
		return "WireGuard 不能搭配 TLS、REALITY、WebSocket 或其他 streamSettings"
	}
	settings, _ := inbound["settings"].(map[string]interface{})
	if settings == nil {
		return "WireGuard 入站缺少 settings"
	}
	if !validWireGuardKey(wireGuardStringValue(settings["secretKey"])) {
		return "WireGuard 服务端私钥必须是 32 字节 Base64 或 64 位十六进制"
	}
	if clients := wireGuardInterfaceSlice(settings["clients"]); len(clients) > 0 {
		return "WireGuard 客户端必须写入 peers，不能使用 clients"
	}

	addresses := wireGuardStringValues(settings["address"])
	if len(addresses) == 0 {
		return "WireGuard 入站至少需要一个服务端隧道地址"
	}
	for index, address := range addresses {
		if !validWireGuardHostCIDR(address) {
			return fmt.Sprintf("WireGuard 服务端地址 #%d 必须使用 IPv4 /32 或 IPv6 /128 主机前缀", index+1)
		}
	}
	if mtu, ok := wireGuardNumericValue(settings["mtu"]); ok && mtu != 0 && (mtu < 576 || mtu > 9000 || mtu != float64(int(mtu))) {
		return "WireGuard MTU 必须是 576 到 9000 之间的整数"
	}

	peers := wireGuardInterfaceSlice(settings["peers"])
	if len(peers) == 0 {
		return "WireGuard 入站至少需要一个客户端 peer"
	}
	seenPublicKeys := make(map[string]struct{})
	seenAllowedIPs := make(map[string]struct{})
	for index, rawPeer := range peers {
		peer, ok := rawPeer.(map[string]interface{})
		if !ok {
			return fmt.Sprintf("WireGuard peer #%d 必须是对象", index+1)
		}
		if privateKey := strings.TrimSpace(wireGuardStringValue(peer["privateKey"])); privateKey != "" {
			return fmt.Sprintf("WireGuard peer #%d 包含客户端私钥；客户端私钥只能保留在客户端配置中", index+1)
		}
		publicKey := strings.TrimSpace(wireGuardStringValue(peer["publicKey"]))
		if !validWireGuardKey(publicKey) {
			return fmt.Sprintf("WireGuard peer #%d 公钥格式无效", index+1)
		}
		if _, duplicate := seenPublicKeys[publicKey]; duplicate {
			return fmt.Sprintf("WireGuard peer #%d 与已有 peer 使用了相同公钥", index+1)
		}
		seenPublicKeys[publicKey] = struct{}{}
		if preSharedKey := strings.TrimSpace(wireGuardStringValue(peer["preSharedKey"])); preSharedKey != "" && !validWireGuardKey(preSharedKey) {
			return fmt.Sprintf("WireGuard peer #%d 预共享密钥格式无效", index+1)
		}
		allowedIPs := wireGuardStringValues(peer["allowedIPs"])
		if len(allowedIPs) == 0 {
			return fmt.Sprintf("WireGuard peer #%d 至少需要一个 allowedIPs 地址", index+1)
		}
		for _, allowedIP := range allowedIPs {
			if !validWireGuardIPOrCIDR(allowedIP) {
				return fmt.Sprintf("WireGuard peer #%d 的 allowedIPs 包含无效 IP/CIDR", index+1)
			}
			normalized := strings.TrimSpace(allowedIP)
			if _, duplicate := seenAllowedIPs[normalized]; duplicate {
				return fmt.Sprintf("WireGuard peer #%d 的 allowedIPs 与已有 peer 重复", index+1)
			}
			seenAllowedIPs[normalized] = struct{}{}
		}
		if keepAlive, ok := wireGuardNumericValue(peer["keepAlive"]); ok && (keepAlive < 0 || keepAlive > 65535 || keepAlive != float64(int(keepAlive))) {
			return fmt.Sprintf("WireGuard peer #%d 的 Keepalive 必须是 0 到 65535 之间的整数", index+1)
		}
	}
	return ""
}

func wireGuardStringValue(value interface{}) string {
	text, _ := value.(string)
	return text
}

func wireGuardInterfaceSlice(value interface{}) []interface{} {
	switch values := value.(type) {
	case []interface{}:
		return values
	case []map[string]interface{}:
		result := make([]interface{}, len(values))
		for index := range values {
			result[index] = values[index]
		}
		return result
	default:
		return nil
	}
}

func wireGuardStringValues(value interface{}) []string {
	switch values := value.(type) {
	case []string:
		return values
	case []interface{}:
		result := make([]string, 0, len(values))
		for _, item := range values {
			if text, ok := item.(string); ok {
				result = append(result, text)
			}
		}
		return result
	default:
		return nil
	}
}

func wireGuardNumericValue(value interface{}) (float64, bool) {
	switch number := value.(type) {
	case float64:
		return number, true
	case float32:
		return float64(number), true
	case int:
		return float64(number), true
	case int32:
		return float64(number), true
	case int64:
		return float64(number), true
	default:
		return 0, false
	}
}

func validWireGuardKey(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) == 64 {
		decoded, err := hex.DecodeString(value)
		return err == nil && len(decoded) == 32
	}
	raw := strings.TrimSuffix(value, "=")
	var decoded []byte
	var err error
	if strings.ContainsAny(raw, "+/") {
		decoded, err = base64.RawStdEncoding.DecodeString(raw)
	} else {
		decoded, err = base64.RawURLEncoding.DecodeString(raw)
	}
	return err == nil && len(decoded) == 32
}

func validWireGuardIPOrCIDR(value string) bool {
	value = strings.TrimSpace(value)
	if net.ParseIP(value) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(value)
	return err == nil
}

func validWireGuardHostCIDR(value string) bool {
	_, network, err := net.ParseCIDR(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	ones, bits := network.Mask.Size()
	return bits > 0 && ones == bits
}
