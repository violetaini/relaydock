package xui

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// ConvertXUIInboundToNodeCandidate builds a RelayDock node and Clash proxy config.
func ConvertXUIInboundToNodeCandidate(ib *XUIInbound, client *XUIClient, serverHost, serverName string) (*ConvertedNodeCandidate, error) {
	if ib.Port <= 0 {
		return nil, fmt.Errorf("inbound port %d is invalid", ib.Port)
	}

	effectiveClient := client
	if effectiveClient == nil && len(ib.Clients) > 0 {
		effectiveClient = &ib.Clients[0]
	}

	host := strings.TrimSpace(serverHost)
	if host == "" {
		host = "127.0.0.1"
	}

	nodeName := ib.Remark
	if nodeName == "" {
		if serverName != "" {
			nodeName = fmt.Sprintf("[%s] %s-%d", serverName, strings.ToUpper(ib.Protocol), ib.Port)
		} else {
			nodeName = fmt.Sprintf("%s-%d", strings.ToUpper(ib.Protocol), ib.Port)
		}
	}

	candidate := &ConvertedNodeCandidate{
		InboundID:   ib.ID,
		ServerName:  serverName,
		ServerHost:  host,
		NodeName:    nodeName,
		NodeType:    ib.Protocol,
		Tag:         ib.Tag,
		Port:        ib.Port,
		Clients:     ib.Clients,
		ProxyConfig: make(map[string]interface{}),
	}

	proxy := candidate.ProxyConfig
	proxy["name"] = nodeName
	proxy["server"] = host
	proxy["port"] = ib.Port
	proxy["udp"] = true

	// Stream settings
	network := "tcp"
	security := "none"
	var realityOpts map[string]interface{}
	sni := ""

	if ib.Stream != nil {
		if ib.Stream.Network != "" {
			network = strings.ToLower(ib.Stream.Network)
		}
		if ib.Stream.Security != "" {
			security = strings.ToLower(ib.Stream.Security)
		}

		if security == "reality" && ib.Stream.RealitySettings != nil {
			rs := ib.Stream.RealitySettings
			realityOpts = make(map[string]interface{})
			pubKey := rs.PublicKey
			if pubKey == "" && rs.PrivateKey != "" {
				derived, err := deriveRealityPublicKey(rs.PrivateKey)
				if err == nil {
					pubKey = derived
				}
			}
			if pubKey != "" {
				realityOpts["public-key"] = pubKey
			}
			if len(rs.ShortIds) > 0 && rs.ShortIds[0] != "" {
				realityOpts["short-id"] = rs.ShortIds[0]
			} else if rs.ShortId != "" {
				realityOpts["short-id"] = rs.ShortId
			}
			if rs.SpiderX != "" {
				realityOpts["spider-x"] = rs.SpiderX
			}
			if len(rs.ServerNames) > 0 && rs.ServerNames[0] != "" {
				sni = rs.ServerNames[0]
			} else if rs.ServerName != "" {
				sni = rs.ServerName
			} else if rs.Dest != "" {
				parts := strings.Split(rs.Dest, ":")
				sni = parts[0]
			}
		}

		if (security == "tls" || security == "reality") && sni == "" && ib.Stream.TLSSettings != nil {
			sni = ib.Stream.TLSSettings.ServerName
		}
	}

	// Protocol specific mapping
	switch ib.Protocol {
	case "vless":
		proxy["type"] = "vless"
		if effectiveClient != nil && effectiveClient.ID != "" {
			proxy["uuid"] = effectiveClient.ID
			if effectiveClient.Flow != "" {
				proxy["flow"] = effectiveClient.Flow
			}
		}
		if network != "" && !strings.EqualFold(network, "tcp") {
			proxy["network"] = network
		}
		if security == "reality" {
			proxy["tls"] = true
			proxy["skip-cert-verify"] = false
			if sni != "" {
				proxy["servername"] = sni
			}
			if len(realityOpts) > 0 {
				proxy["reality-opts"] = realityOpts
			}
			proxy["client-fingerprint"] = "chrome"
		} else if security == "tls" {
			proxy["tls"] = true
			if sni != "" {
				proxy["servername"] = sni
			}
		}
		applyTransportOpts(proxy, ib.Stream)
		candidate.Link = generateVLESSLink(candidate, effectiveClient, sni, realityOpts)

	case "vmess":
		proxy["type"] = "vmess"
		if effectiveClient != nil && effectiveClient.ID != "" {
			proxy["uuid"] = effectiveClient.ID
		}
		proxy["alterId"] = 0
		proxy["cipher"] = "auto"
		if network != "" && !strings.EqualFold(network, "tcp") {
			proxy["network"] = network
		}
		if security == "tls" {
			proxy["tls"] = true
			if sni != "" {
				proxy["servername"] = sni
			}
		}
		applyTransportOpts(proxy, ib.Stream)
		candidate.Link = generateVMessLink(candidate, effectiveClient, sni)

	case "trojan":
		proxy["type"] = "trojan"
		if effectiveClient != nil {
			pwd := effectiveClient.Password
			if pwd == "" {
				pwd = effectiveClient.ID
			}
			proxy["password"] = pwd
		}
		if network != "" && !strings.EqualFold(network, "tcp") {
			proxy["network"] = network
		}
		proxy["tls"] = true
		if sni != "" {
			proxy["sni"] = sni
		}
		applyTransportOpts(proxy, ib.Stream)
		candidate.Link = generateTrojanLink(candidate, effectiveClient, sni)

	case "shadowsocks":
		proxy["type"] = "ss"
		method := "aes-128-gcm"
		password := ""
		if effectiveClient != nil {
			if effectiveClient.Method != "" {
				method = effectiveClient.Method
			}
			password = effectiveClient.Password
			if password == "" {
				password = effectiveClient.ID
			}
		}
		proxy["cipher"] = method
		proxy["password"] = password
		candidate.Link = generateShadowsocksLink(candidate, method, password)

	default:
		proxy["type"] = ib.Protocol
	}

	b, _ := json.Marshal(proxy)
	candidate.ConfigJSON = string(b)

	// Build raw inbound map
	candidate.InboundMap = map[string]interface{}{
		"port":     ib.Port,
		"protocol": ib.Protocol,
		"tag":      ib.Tag,
	}
	if ib.RawSettings != "" {
		var setMap map[string]interface{}
		if err := json.Unmarshal([]byte(ib.RawSettings), &setMap); err == nil {
			candidate.InboundMap["settings"] = setMap
		}
	}
	if ib.RawStreamSettings != "" {
		var streamMap map[string]interface{}
		if err := json.Unmarshal([]byte(ib.RawStreamSettings), &streamMap); err == nil {
			candidate.InboundMap["streamSettings"] = streamMap
		}
	}
	if ib.RawSniffing != "" {
		var sniffMap map[string]interface{}
		if err := json.Unmarshal([]byte(ib.RawSniffing), &sniffMap); err == nil {
			candidate.InboundMap["sniffing"] = sniffMap
		}
	}

	return candidate, nil
}

func applyTransportOpts(proxy map[string]interface{}, stream *XUIStreamSettings) {
	if stream == nil {
		return
	}
	if stream.Network == "ws" && stream.WSSettings != nil {
		wsOpts := map[string]interface{}{}
		if stream.WSSettings.Path != "" {
			wsOpts["path"] = stream.WSSettings.Path
		}
		if len(stream.WSSettings.Headers) > 0 {
			wsOpts["headers"] = stream.WSSettings.Headers
		}
		proxy["ws-opts"] = wsOpts
	} else if stream.Network == "grpc" && stream.GRPCSettings != nil {
		grpcOpts := map[string]interface{}{}
		if stream.GRPCSettings.ServiceName != "" {
			grpcOpts["grpc-service-name"] = stream.GRPCSettings.ServiceName
		}
		proxy["grpc-opts"] = grpcOpts
	}
}

func deriveRealityPublicKey(privateKey string) (string, error) {
	privateKey = strings.TrimSpace(privateKey)
	encodings := []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding}
	var decoded []byte
	var err error
	for _, enc := range encodings {
		decoded, err = enc.DecodeString(privateKey)
		if err == nil && len(decoded) == 32 {
			break
		}
	}
	if len(decoded) != 32 {
		return "", fmt.Errorf("invalid reality private key length: %d", len(decoded))
	}
	priv, err := ecdh.X25519().NewPrivateKey(decoded)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

func generateVLESSLink(candidate *ConvertedNodeCandidate, client *XUIClient, sni string, realityOpts map[string]interface{}) string {
	uuid := ""
	flow := ""
	if client != nil {
		uuid = client.ID
		flow = client.Flow
	}
	u := url.URL{
		Scheme: "vless",
		User:   url.User(uuid),
		Host:   fmt.Sprintf("%s:%d", candidate.ServerHost, candidate.Port),
	}
	q := u.Query()
	q.Set("type", "tcp")
	if len(realityOpts) > 0 {
		q.Set("security", "reality")
		if pbk, ok := realityOpts["public-key"].(string); ok {
			q.Set("pbk", pbk)
		}
		if sid, ok := realityOpts["short-id"].(string); ok {
			q.Set("sid", sid)
		}
		q.Set("fp", "chrome")
	} else {
		q.Set("security", "none")
	}
	if sni != "" {
		q.Set("sni", sni)
	}
	if flow != "" {
		q.Set("flow", flow)
	}
	u.RawQuery = q.Encode()
	u.Fragment = candidate.NodeName
	return u.String()
}

func generateVMessLink(candidate *ConvertedNodeCandidate, client *XUIClient, sni string) string {
	uuid := ""
	if client != nil {
		uuid = client.ID
	}
	m := map[string]interface{}{
		"v":    "2",
		"ps":   candidate.NodeName,
		"add":  candidate.ServerHost,
		"port": candidate.Port,
		"id":   uuid,
		"aid":  0,
		"scy":  "auto",
		"net":  "tcp",
		"type": "none",
		"tls":  "",
	}
	if sni != "" {
		m["tls"] = "tls"
		m["sni"] = sni
	}
	b, _ := json.Marshal(m)
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

func generateTrojanLink(candidate *ConvertedNodeCandidate, client *XUIClient, sni string) string {
	pwd := ""
	if client != nil {
		pwd = client.Password
		if pwd == "" {
			pwd = client.ID
		}
	}
	u := url.URL{
		Scheme: "trojan",
		User:   url.User(pwd),
		Host:   fmt.Sprintf("%s:%d", candidate.ServerHost, candidate.Port),
	}
	q := u.Query()
	q.Set("security", "tls")
	if sni != "" {
		q.Set("sni", sni)
	}
	u.RawQuery = q.Encode()
	u.Fragment = candidate.NodeName
	return u.String()
}

func generateShadowsocksLink(candidate *ConvertedNodeCandidate, method, password string) string {
	raw := fmt.Sprintf("%s:%s", method, password)
	b64 := base64.URLEncoding.EncodeToString([]byte(raw))
	return fmt.Sprintf("ss://%s@%s:%d#%s", b64, candidate.ServerHost, candidate.Port, url.QueryEscape(candidate.NodeName))
}
