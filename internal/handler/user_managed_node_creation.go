package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/violetaini/relaydock/internal/storage"
)

var userManagedInboundTagPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var userManagedDomainLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var userManagedRealityKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var userManagedRealityShortIDPattern = regexp.MustCompile(`^[0-9a-f]{2,16}$`)

type userManagedCreationServer struct {
	ID           int64                     `json:"id"`
	Name         string                    `json:"name"`
	Status       string                    `json:"status"`
	IPAddress    string                    `json:"ip_address,omitempty"`
	IPAddressV6  string                    `json:"ip_address_v6,omitempty"`
	IPv6Enabled  bool                      `json:"ipv6_enabled"`
	Domain       string                    `json:"domain,omitempty"`
	XrayMode     string                    `json:"xray_mode"`
	XrayRunning  bool                      `json:"xray_running"`
	WsConnected  bool                      `json:"ws_connected"`
	Inbounds     []RemoteServerInboundInfo `json:"inbounds"`
	InboundError string                    `json:"inbound_error,omitempty"`
	Grant        managedGrantResponse      `json:"grant"`
}

type userManagedCreationCertificate struct {
	ID             int64    `json:"id"`
	Domain         string   `json:"domain"`
	Status         string   `json:"status"`
	ExpiryDate     *string  `json:"expiry_date,omitempty"`
	RemoteServerID int64    `json:"remote_server_id"`
	DNSNames       []string `json:"dns_names"`
}

func (h *ManagedNodesHandler) activeUserServerGrant(ctx context.Context, username string, serverID int64) (*storage.UserServerGrant, error) {
	grant, err := h.repo.GetUserServerGrantByUserAndServer(ctx, username, serverID)
	if err != nil {
		return nil, err
	}
	user, err := h.repo.GetUser(ctx, username)
	if err != nil {
		return nil, err
	}
	packageActive := false
	if user.AuthorizationMode == storage.AuthorizationModePackage {
		packageActive, err = effectivePackageAssignment(ctx, h.repo, user, time.Now().UTC())
		if err != nil {
			return nil, err
		}
	}
	if !authorizationSourceMatches(user, packageActive, grant.SourceType, grant.SourcePackageID) {
		return nil, storage.ErrManagedGrantInactive
	}
	_, _, billed, err := h.repo.GetUserServerGrantUsage(ctx, grant.ID)
	if err != nil {
		return nil, err
	}
	if state := grant.StateAt(time.Now().UTC(), user.IsActive, billed); state != storage.ManagedGrantActive {
		if state == storage.ManagedGrantOverLimit {
			return nil, storage.ErrManagedTrafficLimit
		}
		return nil, storage.ErrManagedGrantInactive
	}
	return grant, nil
}

func safeInboundInventory(body []byte) ([]RemoteServerInboundInfo, error) {
	var response struct {
		Success  bool                     `json:"success"`
		Inbounds []map[string]interface{} `json:"inbounds"`
	}
	if err := json.Unmarshal(body, &response); err != nil || !response.Success {
		if err == nil {
			err = errors.New("Agent did not return a successful inbound inventory")
		}
		return nil, err
	}
	items := make([]RemoteServerInboundInfo, 0, len(response.Inbounds))
	for _, inbound := range response.Inbounds {
		tag := strings.TrimSpace(wireGuardStringValue(inbound["tag"]))
		if tag == "" || tag == "api" {
			continue
		}
		port, _ := managedNumericInt(inbound["port"])
		items = append(items, RemoteServerInboundInfo{
			Tag: tag, Protocol: canonicalManagedProtocol(wireGuardStringValue(inbound["protocol"])), Port: port,
		})
	}
	return items, nil
}

func managedNumericInt(value interface{}) (int, bool) {
	switch v := value.(type) {
	case float64:
		return int(v), v >= 0 && v <= math.MaxInt && math.Trunc(v) == v
	case int:
		return v, v >= 0
	case json.Number:
		n, err := strconv.Atoi(v.String())
		return n, err == nil && n >= 0
	default:
		return 0, false
	}
}

func validateUserManagedObjectKeys(value map[string]interface{}, scope string, allowed ...string) error {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	for key := range value {
		if _, ok := allowedSet[key]; !ok {
			return fmt.Errorf("%w: unsupported %s field %q", storage.ErrManagedInvalidArgument, scope, key)
		}
	}
	return nil
}

func validateUserManagedStringArray(value interface{}, scope string, maxItems int) error {
	items, ok := value.([]interface{})
	if !ok || len(items) == 0 || len(items) > maxItems {
		return fmt.Errorf("%w: %s must be a non-empty string array", storage.ErrManagedInvalidArgument, scope)
	}
	for _, item := range items {
		text, ok := item.(string)
		if !ok || strings.TrimSpace(text) == "" || len(text) > 253 {
			return fmt.Errorf("%w: invalid %s entry", storage.ErrManagedInvalidArgument, scope)
		}
	}
	return nil
}

func validateUserManagedCredentialPlaceholder(settings map[string]interface{}, key string, allowed ...string) (map[string]interface{}, error) {
	items, ok := settings[key].([]interface{})
	if !ok || len(items) != 1 {
		return nil, fmt.Errorf("%w: settings.%s must contain exactly one credential template", storage.ErrManagedInvalidArgument, key)
	}
	credential, ok := items[0].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("%w: settings.%s credential must be an object", storage.ErrManagedInvalidArgument, key)
	}
	if err := validateUserManagedObjectKeys(credential, "credential", allowed...); err != nil {
		return nil, err
	}
	return credential, nil
}

func validUserManagedDomain(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if len(domain) < 3 || len(domain) > 253 || !strings.Contains(domain, ".") || strings.Contains(domain, "..") || net.ParseIP(domain) != nil {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || !userManagedDomainLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func validatePublicUserManagedRealityDomain(ctx context.Context, domain string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if !validUserManagedDomain(domain) {
		return fmt.Errorf("%w: invalid Reality target domain", storage.ErrManagedInvalidArgument)
	}
	addresses, err := resolvePublicFederationHost(ctx, domain)
	if err != nil {
		return fmt.Errorf("%w: Reality target must resolve only to public addresses", storage.ErrManagedInvalidArgument)
	}
	if err := validateUserManagedRealityResolvedAddresses(domain, addresses); err != nil {
		return err
	}
	return nil
}

func validateUserManagedRealityResolvedAddresses(domain string, addresses []net.IPAddr) error {
	if !validUserManagedDomain(domain) || len(addresses) == 0 {
		return fmt.Errorf("%w: invalid Reality target domain", storage.ErrManagedInvalidArgument)
	}
	for _, address := range addresses {
		if !isPublicFederationIP(address.IP) {
			return fmt.Errorf("%w: Reality target must resolve only to public addresses", storage.ErrManagedInvalidArgument)
		}
	}
	return nil
}

func userManagedRealityTargetDomain(inbound map[string]interface{}) (string, bool, error) {
	stream, _ := inbound["streamSettings"].(map[string]interface{})
	if strings.ToLower(strings.TrimSpace(wireGuardStringValue(stream["security"]))) != "reality" {
		return "", false, nil
	}
	reality, _ := stream["realitySettings"].(map[string]interface{})
	if reality == nil {
		return "", true, fmt.Errorf("%w: realitySettings are required", storage.ErrManagedInvalidArgument)
	}
	target := strings.TrimSpace(wireGuardStringValue(reality["target"]))
	host, port, err := net.SplitHostPort(target)
	host = strings.ToLower(strings.TrimSpace(host))
	if err != nil || port != "443" || !validUserManagedDomain(host) {
		return "", true, fmt.Errorf("%w: Reality target must be a public domain on port 443", storage.ErrManagedInvalidArgument)
	}
	serverNames, ok := reality["serverNames"].([]interface{})
	if !ok || len(serverNames) != 1 || !strings.EqualFold(strings.TrimSpace(wireGuardStringValue(serverNames[0])), host) {
		return "", true, fmt.Errorf("%w: Reality serverNames must match target", storage.ErrManagedInvalidArgument)
	}
	shortIDs, ok := reality["shortIds"].([]interface{})
	shortID := ""
	if ok && len(shortIDs) == 1 {
		shortID = strings.ToLower(strings.TrimSpace(wireGuardStringValue(shortIDs[0])))
	}
	if !ok || len(shortIDs) != 1 || !userManagedRealityShortIDPattern.MatchString(shortID) || len(shortID)%2 != 0 {
		return "", true, fmt.Errorf("%w: invalid Reality short ID", storage.ErrManagedInvalidArgument)
	}
	show, showOK := reality["show"].(bool)
	xver, xverOK := managedNumericInt(reality["xver"])
	if !showOK || show || !xverOK || xver != 0 || !userManagedRealityKeyPattern.MatchString(strings.TrimSpace(wireGuardStringValue(reality["privateKey"]))) {
		return "", true, fmt.Errorf("%w: invalid Reality settings", storage.ErrManagedInvalidArgument)
	}
	return host, true, nil
}

func exactUserManagedStringArray(value interface{}, expected ...string) bool {
	items, ok := value.([]interface{})
	if !ok || len(items) != len(expected) {
		return false
	}
	for index := range items {
		if wireGuardStringValue(items[index]) != expected[index] {
			return false
		}
	}
	return true
}

func userManagedStreamChild(stream map[string]interface{}, key string, required bool) (map[string]interface{}, error) {
	raw, exists := stream[key]
	if !exists {
		if required {
			return nil, fmt.Errorf("%w: %s is required", storage.ErrManagedInvalidArgument, key)
		}
		return nil, nil
	}
	if !required {
		return nil, fmt.Errorf("%w: %s is not valid for this protocol profile", storage.ErrManagedInvalidArgument, key)
	}
	value, ok := raw.(map[string]interface{})
	if !ok || value == nil {
		return nil, fmt.Errorf("%w: invalid %s", storage.ErrManagedInvalidArgument, key)
	}
	return value, nil
}

func validateUserManagedStreamProfile(inbound map[string]interface{}, protocol, listen string, credential map[string]interface{}) error {
	streamRaw, hasStream := inbound["streamSettings"]
	if !hasStream {
		switch protocol {
		case "shadowsocks", "socks", "http":
			if listen != "0.0.0.0" {
				return fmt.Errorf("%w: invalid listen address for protocol", storage.ErrManagedInvalidArgument)
			}
			if _, hasCertificate := inbound["cert_id"]; hasCertificate {
				return fmt.Errorf("%w: cert_id is only valid for TLS", storage.ErrManagedInvalidArgument)
			}
			return nil
		default:
			return fmt.Errorf("%w: streamSettings are required for protocol", storage.ErrManagedInvalidArgument)
		}
	}
	stream, ok := streamRaw.(map[string]interface{})
	if !ok || validateUserManagedObjectKeys(stream, "streamSettings", "network", "security", "tlsSettings", "realitySettings", "wsSettings", "grpcSettings", "hysteriaSettings") != nil {
		return fmt.Errorf("%w: invalid streamSettings", storage.ErrManagedInvalidArgument)
	}
	network := strings.ToLower(strings.TrimSpace(wireGuardStringValue(stream["network"])))
	security := strings.ToLower(strings.TrimSpace(wireGuardStringValue(stream["security"])))
	validProfile := false
	switch protocol {
	case "vless":
		validProfile = network == "tcp" && (security == "tls" || security == "reality") || network == "grpc" && security == "tls" || network == "ws" && security == "none"
	case "vmess":
		validProfile = network == "tcp" && (security == "none" || security == "tls") || network == "grpc" && security == "tls" || network == "ws" && security == "none"
	case "trojan":
		validProfile = network == "tcp" && (security == "tls" || security == "reality") || network == "grpc" && security == "tls" || network == "ws" && security == "none"
	case "hysteria":
		validProfile = network == "hysteria" && security == "tls"
	}
	if !validProfile {
		return fmt.Errorf("%w: unsupported protocol, transport, and security combination", storage.ErrManagedInvalidArgument)
	}
	if listen != "0.0.0.0" && !(network == "ws" && security == "none" && listen == "127.0.0.1") {
		return fmt.Errorf("%w: invalid listen address for protocol profile", storage.ErrManagedInvalidArgument)
	}
	if protocol == "trojan" && network == "ws" && listen != "127.0.0.1" {
		return fmt.Errorf("%w: Trojan WebSocket is only supported behind managed TLS", storage.ErrManagedInvalidArgument)
	}
	if _, hasCertificate := inbound["cert_id"]; hasCertificate != (security == "tls") {
		return fmt.Errorf("%w: cert_id must be present only for TLS profiles", storage.ErrManagedInvalidArgument)
	}
	tls, err := userManagedStreamChild(stream, "tlsSettings", security == "tls")
	if err != nil {
		return err
	}
	reality, err := userManagedStreamChild(stream, "realitySettings", security == "reality")
	if err != nil {
		return err
	}
	ws, err := userManagedStreamChild(stream, "wsSettings", network == "ws")
	if err != nil {
		return err
	}
	grpc, err := userManagedStreamChild(stream, "grpcSettings", network == "grpc")
	if err != nil {
		return err
	}
	hysteria, err := userManagedStreamChild(stream, "hysteriaSettings", network == "hysteria")
	if err != nil {
		return err
	}
	if tls != nil {
		if err := validateUserManagedObjectKeys(tls, "tlsSettings", "serverName", "alpn"); err != nil {
			return err
		}
		if !validUserManagedDomain(wireGuardStringValue(tls["serverName"])) {
			return fmt.Errorf("%w: invalid TLS serverName", storage.ErrManagedInvalidArgument)
		}
		expectedALPN := []string{"h2", "http/1.1"}
		if network == "grpc" {
			expectedALPN = []string{"h2"}
		} else if network == "hysteria" {
			expectedALPN = []string{"h3"}
		}
		if !exactUserManagedStringArray(tls["alpn"], expectedALPN...) {
			return fmt.Errorf("%w: invalid TLS ALPN for transport", storage.ErrManagedInvalidArgument)
		}
	}
	if reality != nil {
		if err := validateUserManagedObjectKeys(reality, "realitySettings", "show", "target", "xver", "serverNames", "privateKey", "shortIds"); err != nil {
			return err
		}
		if _, _, err := userManagedRealityTargetDomain(inbound); err != nil {
			return err
		}
	}
	if ws != nil {
		if err := validateUserManagedObjectKeys(ws, "wsSettings", "path", "host"); err != nil {
			return err
		}
		path := strings.TrimSpace(wireGuardStringValue(ws["path"]))
		if len(path) < 2 || len(path) > 1024 || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, " \t\r\n?#") {
			return fmt.Errorf("%w: invalid WebSocket path", storage.ErrManagedInvalidArgument)
		}
		host := strings.TrimSpace(wireGuardStringValue(ws["host"]))
		if listen == "127.0.0.1" && !validUserManagedDomain(host) {
			return fmt.Errorf("%w: managed WSS requires a valid domain", storage.ErrManagedInvalidArgument)
		}
		if host != "" && (len(host) > 253 || strings.ContainsAny(host, " \t\r\n/?#") || strings.Contains(host, "://")) {
			return fmt.Errorf("%w: invalid WebSocket host", storage.ErrManagedInvalidArgument)
		}
	}
	if grpc != nil {
		if err := validateUserManagedObjectKeys(grpc, "grpcSettings", "serviceName", "multiMode"); err != nil {
			return err
		}
		serviceName := strings.TrimSpace(wireGuardStringValue(grpc["serviceName"]))
		multiMode, multiModeOK := grpc["multiMode"].(bool)
		if serviceName == "" || len(serviceName) > 1023 || strings.ContainsAny(serviceName, " \t\r\n?#") || !multiModeOK || multiMode {
			return fmt.Errorf("%w: invalid gRPC settings", storage.ErrManagedInvalidArgument)
		}
	}
	if hysteria != nil {
		if err := validateUserManagedObjectKeys(hysteria, "hysteriaSettings", "version"); err != nil {
			return err
		}
		version, versionOK := managedNumericInt(hysteria["version"])
		if !versionOK || version != 2 {
			return fmt.Errorf("%w: invalid Hysteria2 transport", storage.ErrManagedInvalidArgument)
		}
	}
	flow := strings.TrimSpace(wireGuardStringValue(credential["flow"]))
	if flow != "" && !(protocol == "vless" && network == "tcp" && (security == "tls" || security == "reality")) {
		return fmt.Errorf("%w: VLESS flow is not supported by this profile", storage.ErrManagedInvalidArgument)
	}
	return nil
}

// validateUserManagedInboundShape accepts only the fields emitted by the
// panel's managed-node preset builder. Credentials are validated as templates
// and replaced later; low-level Xray escape hatches such as fallbacks, sockopt,
// inline certificates, arbitrary file paths, and routing fragments are denied.
func validateUserManagedInboundShape(request map[string]interface{}) (map[string]interface{}, map[string]interface{}, string, string, error) {
	if err := validateUserManagedCreateKeys(request); err != nil {
		return nil, nil, "", "", err
	}
	nodeName, ok := request["node_name"].(string)
	nodeName = strings.TrimSpace(nodeName)
	if !ok || nodeName == "" || len(nodeName) > 128 {
		return nil, nil, "", "", fmt.Errorf("%w: invalid node_name", storage.ErrManagedInvalidArgument)
	}
	request["node_name"] = nodeName
	ipVersion := "v4"
	if value, exists := request["ip_version"]; exists {
		var valid bool
		ipVersion, valid = value.(string)
		ipVersion = strings.ToLower(strings.TrimSpace(ipVersion))
		if !valid || ipVersion != "v4" && ipVersion != "v6" && ipVersion != "both" {
			return nil, nil, "", "", fmt.Errorf("%w: invalid ip_version", storage.ErrManagedInvalidArgument)
		}
	}
	request["ip_version"] = ipVersion
	if raw, exists := request["client_options"]; exists {
		options, ok := raw.(map[string]interface{})
		if !ok || validateUserManagedObjectKeys(options, "client_options", "skip_cert_verify") != nil {
			return nil, nil, "", "", fmt.Errorf("%w: invalid client_options", storage.ErrManagedInvalidArgument)
		}
		if skip, exists := options["skip_cert_verify"]; exists {
			if _, ok := skip.(bool); !ok {
				return nil, nil, "", "", fmt.Errorf("%w: invalid client_options.skip_cert_verify", storage.ErrManagedInvalidArgument)
			}
		}
	}
	inbound, ok := request["inbound"].(map[string]interface{})
	if !ok || inbound == nil {
		return nil, nil, "", "", fmt.Errorf("%w: inbound is required", storage.ErrManagedInvalidArgument)
	}
	if err := validateUserManagedObjectKeys(inbound, "inbound", "tag", "listen", "port", "protocol", "settings", "sniffing", "streamSettings", "cert_id"); err != nil {
		return nil, nil, "", "", err
	}
	tag := strings.TrimSpace(wireGuardStringValue(inbound["tag"]))
	protocol := canonicalManagedProtocol(wireGuardStringValue(inbound["protocol"]))
	if !userManagedInboundTagPattern.MatchString(tag) || tag == "api" || strings.HasPrefix(strings.ToLower(tag), "anydoor-") {
		return nil, nil, "", "", fmt.Errorf("%w: invalid inbound tag", storage.ErrManagedInvalidArgument)
	}
	switch protocol {
	case "vless", "vmess", "trojan", "shadowsocks", "hysteria", "socks", "http":
	default:
		return nil, nil, "", "", fmt.Errorf("%w: unsupported inbound protocol", storage.ErrManagedInvalidArgument)
	}
	listen, ok := inbound["listen"].(string)
	if !ok || listen != "0.0.0.0" && listen != "127.0.0.1" {
		return nil, nil, "", "", fmt.Errorf("%w: invalid inbound listen address", storage.ErrManagedInvalidArgument)
	}
	port, ok := managedNumericInt(inbound["port"])
	if !ok || port < 1 || port > 65535 {
		return nil, nil, "", "", fmt.Errorf("%w: invalid inbound port", storage.ErrManagedInvalidArgument)
	}
	inbound["tag"], inbound["protocol"], inbound["port"] = tag, protocol, port
	settings, ok := inbound["settings"].(map[string]interface{})
	if !ok || settings == nil {
		return nil, nil, "", "", fmt.Errorf("%w: inbound settings are required", storage.ErrManagedInvalidArgument)
	}
	var credential map[string]interface{}
	var err error
	switch protocol {
	case "vless":
		if err = validateUserManagedObjectKeys(settings, "settings", "clients", "decryption"); err == nil {
			credential, err = validateUserManagedCredentialPlaceholder(settings, "clients", "id", "email", "level", "flow")
		}
		if err == nil && wireGuardStringValue(settings["decryption"]) != "none" {
			err = fmt.Errorf("%w: vless decryption must be none", storage.ErrManagedInvalidArgument)
		}
	case "vmess":
		if err = validateUserManagedObjectKeys(settings, "settings", "clients"); err == nil {
			credential, err = validateUserManagedCredentialPlaceholder(settings, "clients", "id", "email", "level", "security")
		}
	case "trojan":
		if err = validateUserManagedObjectKeys(settings, "settings", "clients"); err == nil {
			credential, err = validateUserManagedCredentialPlaceholder(settings, "clients", "password", "email", "level")
		}
	case "shadowsocks":
		if err = validateUserManagedObjectKeys(settings, "settings", "clients", "method", "password", "network"); err == nil {
			credential, err = validateUserManagedCredentialPlaceholder(settings, "clients", "method", "password", "email", "level")
		}
		method := strings.ToLower(strings.TrimSpace(wireGuardStringValue(settings["method"])))
		if method == "" && credential != nil {
			method = strings.ToLower(strings.TrimSpace(wireGuardStringValue(credential["method"])))
		}
		if err == nil && method == "chacha20-ietf-poly1305" {
			err = fmt.Errorf("%w: shared Shadowsocks cipher is not eligible for isolated credentials", storage.ErrManagedInvalidArgument)
		}
		if err == nil && wireGuardStringValue(settings["network"]) != "tcp,udp" {
			err = fmt.Errorf("%w: shadowsocks network must be tcp,udp", storage.ErrManagedInvalidArgument)
		}
	case "hysteria":
		if err = validateUserManagedObjectKeys(settings, "settings", "version", "clients"); err == nil {
			credential, err = validateUserManagedCredentialPlaceholder(settings, "clients", "auth", "email", "level")
		}
		if version, valid := managedNumericInt(settings["version"]); err == nil && (!valid || version != 2) {
			err = fmt.Errorf("%w: only Hysteria2 is supported", storage.ErrManagedInvalidArgument)
		}
	case "socks":
		if err = validateUserManagedObjectKeys(settings, "settings", "auth", "accounts", "udp"); err == nil {
			credential, err = validateUserManagedCredentialPlaceholder(settings, "accounts", "user", "pass")
		}
		if err == nil && wireGuardStringValue(settings["auth"]) != "password" {
			err = fmt.Errorf("%w: socks auth must be password", storage.ErrManagedInvalidArgument)
		}
		if _, valid := settings["udp"].(bool); err == nil && !valid {
			err = fmt.Errorf("%w: socks udp must be a boolean", storage.ErrManagedInvalidArgument)
		}
	case "http":
		if err = validateUserManagedObjectKeys(settings, "settings", "accounts", "allowTransparent"); err == nil {
			credential, err = validateUserManagedCredentialPlaceholder(settings, "accounts", "user", "pass")
		}
		if transparent, valid := settings["allowTransparent"].(bool); err == nil && (!valid || transparent) {
			err = fmt.Errorf("%w: transparent HTTP proxy is not allowed", storage.ErrManagedInvalidArgument)
		}
	}
	if err != nil {
		return nil, nil, "", "", err
	}
	if flow := strings.TrimSpace(wireGuardStringValue(credential["flow"])); flow != "" && flow != "xtls-rprx-vision" {
		return nil, nil, "", "", fmt.Errorf("%w: unsupported VLESS flow", storage.ErrManagedInvalidArgument)
	}
	if protocol == "vmess" {
		security := strings.ToLower(strings.TrimSpace(wireGuardStringValue(credential["security"])))
		if security != "auto" && security != "aes-128-gcm" && security != "chacha20-poly1305" {
			return nil, nil, "", "", fmt.Errorf("%w: unsupported VMess security", storage.ErrManagedInvalidArgument)
		}
	}
	if sniffingRaw, exists := inbound["sniffing"]; exists {
		sniffing, ok := sniffingRaw.(map[string]interface{})
		if !ok || validateUserManagedObjectKeys(sniffing, "sniffing", "enabled", "destOverride", "routeOnly") != nil {
			return nil, nil, "", "", fmt.Errorf("%w: invalid sniffing settings", storage.ErrManagedInvalidArgument)
		}
	}
	delete(inbound, "sniffing")
	if err := validateUserManagedStreamProfile(inbound, protocol, listen, credential); err != nil {
		return nil, nil, "", "", err
	}
	return inbound, settings, tag, protocol, nil
}

func (h *ManagedNodesHandler) userManagedCreationContext(ctx context.Context, username string) (map[string]interface{}, error) {
	responses, err := h.grantResponses(ctx, username)
	if err != nil {
		return nil, err
	}
	servers := make([]userManagedCreationServer, 0, len(responses))
	allowedServers := make(map[int64]struct{}, len(responses))
	for _, grantResponse := range responses {
		if grantResponse.State != storage.ManagedGrantActive {
			continue
		}
		if _, err := h.activeUserServerGrant(ctx, username, grantResponse.ServerID); err != nil {
			continue
		}
		server, err := h.repo.GetRemoteServer(ctx, grantResponse.ServerID)
		if err != nil {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(server.XrayMode), "embedded") {
			continue
		}
		item := userManagedCreationServer{
			ID: server.ID, Name: server.Name, Status: server.Status,
			IPAddress: server.IPAddress, IPAddressV6: server.IPAddressV6,
			IPv6Enabled: server.IPv6Enabled, Domain: server.Domain,
			XrayMode: server.XrayMode, XrayRunning: server.XrayRunning,
			Grant: grantResponse, Inbounds: []RemoteServerInboundInfo{},
		}
		if h.remoteManage != nil && h.remoteManage.wsHandler != nil {
			item.WsConnected = h.remoteManage.wsHandler.IsConnected(server.Token)
		}
		if h.remoteManage != nil {
			body, fetchErr := h.remoteManage.forwardToRemoteServer(ctx, server.ID, http.MethodGet, "/api/child/inbounds", nil)
			if fetchErr != nil {
				item.InboundError = fetchErr.Error()
			} else if item.Inbounds, fetchErr = safeInboundInventory(body); fetchErr != nil {
				item.InboundError = fetchErr.Error()
			}
		}
		servers = append(servers, item)
		allowedServers[server.ID] = struct{}{}
	}
	certificates := make([]userManagedCreationCertificate, 0)
	if certs, certErr := h.repo.ListValidCertificates(ctx); certErr == nil {
		for i := range certs {
			cert := &certs[i]
			if cert.RemoteServerID > 0 {
				if _, ok := allowedServers[cert.RemoteServerID]; !ok {
					continue
				}
			}
			item := userManagedCreationCertificate{
				ID: cert.ID, Domain: cert.Domain, Status: cert.Status,
				RemoteServerID: cert.RemoteServerID, DNSNames: certificateDNSNames(cert.CertPEM),
			}
			if cert.ExpiryDate != nil {
				value := cert.ExpiryDate.UTC().Format(time.RFC3339)
				item.ExpiryDate = &value
			}
			certificates = append(certificates, item)
		}
	}
	creations, err := h.repo.ListUserManagedNodeCreations(ctx, username, 0)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"success": true, "servers": servers, "certificates": certificates, "creations": creations,
	}, nil
}

func replaceInboundCredential(settings map[string]interface{}, protocol string, credential map[string]interface{}) error {
	if settings == nil || credential == nil {
		return storage.ErrManagedInvalidArgument
	}
	for _, key := range []string{"clients", "users", "accounts"} {
		delete(settings, key)
	}
	key := "clients"
	switch canonicalManagedProtocol(protocol) {
	case "snell", "anytls":
		key = "users"
	case "socks", "http":
		key = "accounts"
	case "vless", "vmess", "trojan", "hysteria", "shadowsocks":
		// clients
	default:
		return fmt.Errorf("%w: protocol does not support isolated credentials", storage.ErrManagedInvalidArgument)
	}
	settings[key] = []interface{}{credential}
	return nil
}

func copyManagedCredentialOptions(protocol string, settings, credential map[string]interface{}) {
	var source map[string]interface{}
	for _, key := range []string{"clients", "users", "accounts"} {
		if values, _ := settings[key].([]interface{}); len(values) > 0 {
			source, _ = values[0].(map[string]interface{})
			if source != nil {
				break
			}
		}
	}
	if source == nil {
		return
	}
	keys := []string{"flow"}
	switch canonicalManagedProtocol(protocol) {
	case "vmess":
		keys = []string{"security"}
	case "snell":
		keys = []string{"version", "obfsMode", "obfsHost", "v6Mode"}
	}
	for _, key := range keys {
		if value, ok := source[key]; ok {
			credential[key] = value
		}
	}
}

func validateUserManagedCreateKeys(request map[string]interface{}) error {
	allowed := map[string]bool{
		"action": true, "node_name": true, "inbound": true,
		"client_options": true, "ip_version": true,
	}
	for key := range request {
		if !allowed[key] {
			return fmt.Errorf("%w: unsupported creation field %q", storage.ErrManagedInvalidArgument, key)
		}
	}
	return nil
}

func (h *ManagedNodesHandler) validateUserManagedCertificate(ctx context.Context, serverID int64, inbound map[string]interface{}) error {
	stream, _ := inbound["streamSettings"].(map[string]interface{})
	security := strings.ToLower(strings.TrimSpace(wireGuardStringValue(stream["security"])))
	rawID, hasCertificate := inbound["cert_id"]
	if security != "tls" {
		if hasCertificate {
			return fmt.Errorf("%w: cert_id is only valid for TLS", storage.ErrManagedInvalidArgument)
		}
		return nil
	}
	certificateID, ok := managedNumericInt(rawID)
	if !ok || certificateID <= 0 {
		return fmt.Errorf("%w: a managed TLS certificate is required", storage.ErrManagedInvalidArgument)
	}
	certificate, err := h.repo.GetCertificate(ctx, int64(certificateID))
	if err != nil || certificate == nil || certificate.Status != storage.CertStatusValid ||
		certificate.RemoteServerID != 0 && certificate.RemoteServerID != serverID ||
		certificate.ExpiryDate != nil && !certificate.ExpiryDate.After(time.Now().UTC()) {
		return fmt.Errorf("%w: certificate is unavailable for this server", storage.ErrManagedInvalidArgument)
	}
	return nil
}

func (h *ManagedNodesHandler) cleanupFailedUserManagedCreation(r *http.Request, creation *storage.UserManagedNodeCreation, server *storage.RemoteServer, node *storage.Node, selection *storage.UserNodeSelection, cleanupSourceID, credentialID int64) error {
	var failures []error
	if selection != nil {
		deleting, err := h.repo.MarkUserManagedNodeCreationDeleting(r.Context(), creation.ID, "creation did not reach an active managed policy")
		if err != nil {
			return err
		}
		// Once a selection exists, first reconcile it back to deny/inactive. Only
		// then may cleanup remove the remote inbound. This keeps a failed normal
		// limiter publish from leaving a live credential without a restrictive
		// policy when remote rollback also fails.
		return h.cleanupUserManagedNodeCreationLocked(r.Context(), *deleting, creation.Username)
	}
	if node != nil && server != nil && h.remoteManage != nil {
		// The response node is untrusted until every ownership field is checked.
		// Rollback must always use the immutable reservation fence.
		if err := h.remoteManage.rollbackManagedNode(r, server.ID, server.Name, creation.InboundTag, creation.MutationID); err != nil {
			failures = append(failures, err)
			_, _ = h.repo.MarkUserManagedNodeCreationDeleting(r.Context(), creation.ID, err.Error())
			return errors.Join(failures...)
		}
	}
	if selection != nil {
		if result, err := h.repo.DeactivateUserNodeSelection(r.Context(), creation.Username, selection.ID,
			creation.Username, storage.ManagedSuspendAdminDisabled, time.Now().UTC()); err == nil {
			_, _ = h.repo.MarkUserInboundAccessSourceApplied(r.Context(), result.Source.ID,
				result.Source.Generation, storage.ManagedObservedInactive, time.Now().UTC())
		} else {
			failures = append(failures, err)
		}
	}
	if cleanupSourceID > 0 && credentialID > 0 {
		if err := h.repo.DeletePackageInboundCredentialCleanupSourceForPromotion(r.Context(), cleanupSourceID, credentialID); err != nil && !errors.Is(err, storage.ErrManagedAccessSourceNotFound) {
			failures = append(failures, err)
		}
	}
	if recovered, err := h.repo.RecoverUserManagedNodeCreationLinks(r.Context(), creation.ID); err == nil {
		creation = recovered
	}
	if creation.SelectionID != nil || creation.OfferID != nil {
		if err := h.repo.DeleteUserManagedNodeCreationGraph(r.Context(), creation.ID); err != nil {
			failures = append(failures, err)
		}
	} else {
		if credentialID > 0 {
			_ = h.repo.DeleteUserInboundConfig(r.Context(), creation.Username, creation.ServerID, creation.InboundTag)
		}
		if err := h.repo.CancelUserManagedNodeCreation(r.Context(), creation.ID); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (h *ManagedNodesHandler) ensureUserManagedInboundAvailable(ctx context.Context, server *storage.RemoteServer, tag string, port int) error {
	if h.remoteManage == nil || server == nil {
		return errors.New("remote manager is not available")
	}
	desiredInbounds, err := h.repo.ListActiveDesiredInbounds(ctx, server.ID)
	if err != nil {
		return err
	}
	for _, desired := range desiredInbounds {
		if desired.InboundTag == tag {
			// Desired state is control-plane authority even when an old or corrupt
			// row has lost its mutation token and the runtime inventory is empty.
			// Never overwrite that generation by treating missing ownership as free.
			return fmt.Errorf("%w: inbound tag %s already has active desired state", storage.ErrManagedAccessConflict, tag)
		}
		if port <= 0 {
			continue
		}
		inbound, decodeErr := decodeDesiredInbound(desired.InboundJSON)
		if decodeErr != nil {
			return fmt.Errorf("inspect active desired inbound %s: %w", desired.InboundTag, decodeErr)
		}
		desiredPort, ok := managedNumericInt(inbound["port"])
		if !ok || desiredPort <= 0 {
			return fmt.Errorf("%w: active desired inbound %s has an invalid port", storage.ErrManagedAccessConflict, desired.InboundTag)
		}
		if desiredPort == port {
			return fmt.Errorf("%w: inbound port %d already has active desired state", storage.ErrManagedAccessConflict, port)
		}
	}
	if _, found, err := h.remoteManage.findManagedNode(ctx, server.Name, tag); err != nil {
		return err
	} else if found {
		return fmt.Errorf("%w: inbound tag %s already exists", storage.ErrManagedAccessConflict, tag)
	}
	if mutationID, err := h.repo.FindInboundMutationID(ctx, server.ID, tag); err != nil {
		return err
	} else if strings.TrimSpace(mutationID) != "" {
		return fmt.Errorf("%w: inbound tag %s already has database ownership", storage.ErrManagedAccessConflict, tag)
	}
	body, err := h.remoteManage.forwardToRemoteServer(ctx, server.ID, http.MethodGet, "/api/child/inbounds", nil)
	if err != nil {
		return err
	}
	inbounds, err := safeInboundInventory(body)
	if err != nil {
		return err
	}
	for _, existing := range inbounds {
		if existing.Tag == tag || port > 0 && existing.Port == port {
			return fmt.Errorf("%w: inbound tag or port is already in use", storage.ErrManagedAccessConflict)
		}
	}
	return nil
}

func (h *ManagedNodesHandler) validateUserManagedNodeProfile(grant *storage.UserServerGrant, inbound map[string]interface{}, server *storage.RemoteServer, identity string) error {
	if grant == nil || server == nil || h.remoteManage == nil {
		return storage.ErrManagedInvalidArgument
	}
	profileInbound := make(map[string]interface{}, len(inbound))
	for key, value := range inbound {
		profileInbound[key] = value
	}
	profileHost, profilePort := chooseClashServerHost(server), 0
	if effectivePort, effectiveHost := applyWSSClientRewrite(profileInbound, server); effectivePort > 0 {
		profileHost, profilePort = effectiveHost, effectivePort
	}
	proxy, err := h.remoteManage.inboundToClashProxy(profileInbound, profileHost, server.Name, profilePort, identity)
	if err != nil {
		return err
	}
	proxyJSON, err := json.Marshal(proxy)
	if err != nil {
		return err
	}
	protocol := canonicalManagedProtocol(wireGuardStringValue(inbound["protocol"]))
	if !grant.AllowsNodeProtocol(protocol, string(proxyJSON)) || !storage.SelfServiceNodeProtocolEligible(protocol, string(proxyJSON)) {
		return fmt.Errorf("%w: %s", storage.ErrManagedProtocolNotAllowed, protocol)
	}
	return nil
}

func (h *ManagedNodesHandler) createUserManagedNode(w http.ResponseWriter, r *http.Request, username string) {
	serverID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("server_id")), 10, 64)
	if err != nil || serverID <= 0 {
		writeManagedError(w, storage.ErrManagedInvalidArgument)
		return
	}
	leasedCtx, releaseAuthorization, err := h.repo.AcquireUserAuthorizationLease(r.Context(), username)
	if err != nil {
		writeManagedError(w, err)
		return
	}
	defer releaseAuthorization()
	leasedCtx, releaseServer, err := h.repo.AcquireRemoteServerExclusiveMutationLease(leasedCtx, serverID)
	if err != nil {
		writeManagedError(w, err)
		return
	}
	defer releaseServer()
	r = r.Clone(leasedCtx)
	if h.remoteManage == nil || h.limiter == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "managed node creation is unavailable")
		return
	}
	grant, err := h.activeUserServerGrant(r.Context(), username, serverID)
	if err != nil {
		writeManagedError(w, err)
		return
	}
	server, err := h.repo.GetRemoteServer(r.Context(), serverID)
	if err != nil {
		writeManagedError(w, err)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(server.XrayMode), "embedded") {
		writeManagedError(w, storage.ErrManagedServerMismatch)
		return
	}
	if err := h.requireManagedAgentCapabilities(r.Context(), serverID); err != nil {
		writeManagedError(w, err)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeManagedError(w, storage.ErrManagedInvalidArgument)
		return
	}
	var request map[string]interface{}
	if json.Unmarshal(body, &request) != nil {
		writeManagedError(w, storage.ErrManagedInvalidArgument)
		return
	}
	action := strings.ToLower(strings.TrimSpace(wireGuardStringValue(request["action"])))
	if action != "" && action != "add" {
		writeManagedError(w, storage.ErrManagedInvalidArgument)
		return
	}
	request["action"] = "add"
	inbound, settings, tag, protocol, err := validateUserManagedInboundShape(request)
	if err != nil {
		writeManagedError(w, err)
		return
	}
	if domain, reality, err := userManagedRealityTargetDomain(inbound); err != nil {
		writeManagedError(w, err)
		return
	} else if reality {
		resolver := h.realityResolver
		if resolver == nil {
			resolver = validatePublicUserManagedRealityDomain
		}
		if err := resolver(r.Context(), domain); err != nil {
			writeManagedError(w, err)
			return
		}
		candidates, err := h.collectUserManagedRealityDomainCandidates(r.Context(), serverID)
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "selected server Reality candidates are unavailable")
			return
		}
		approved := false
		for _, candidate := range candidates {
			if strings.EqualFold(candidate, domain) {
				approved = true
				break
			}
		}
		if !approved {
			writeJSONError(w, http.StatusBadRequest, "Reality target is not approved for the selected server")
			return
		}
		results, err := h.probeUserManagedRealityDomains(r.Context(), serverID, []string{domain}, 2000)
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "selected server could not probe the Reality target")
			return
		}
		if len(results) != 1 || !results[0].Success || !strings.EqualFold(results[0].Domain, domain) {
			writeJSONError(w, http.StatusBadRequest, "Reality target is not a reachable public TLS endpoint on the selected server")
			return
		}
	}
	if err := h.validateUserManagedCertificate(r.Context(), serverID, inbound); err != nil {
		writeManagedError(w, err)
		return
	}
	if !grant.AllowsProtocol(protocol) || !supportsPerUserInboundCredential(protocol) {
		writeManagedError(w, fmt.Errorf("%w: %s", storage.ErrManagedProtocolNotAllowed, protocol))
		return
	}
	port, _ := managedNumericInt(inbound["port"])
	if isNginxManagedWSSInbound(inbound) {
		// The submitted 443 is a public client port. The server-side WSS
		// preprocessor allocates a distinct loopback Xray port under the same
		// mutation lease, so it must not collide with another public 443 listener.
		port = 0
	}
	if err := h.ensureUserManagedInboundAvailable(r.Context(), server, tag, port); err != nil {
		writeManagedError(w, err)
		return
	}
	mutationID := "user-managed-node:" + uuid.NewString()
	creation, err := h.repo.ReserveUserManagedNodeCreation(r.Context(), username, grant.ID, serverID, tag, mutationID, time.Now().UTC())
	if err != nil {
		writeManagedError(w, err)
		return
	}
	user, err := h.repo.GetUser(r.Context(), username)
	if err != nil {
		_ = h.repo.CancelUserManagedNodeCreation(r.Context(), creation.ID)
		writeManagedError(w, err)
		return
	}
	credential, _, _, err := getOrCreateInboundCredential(r.Context(), h.repo, user, serverID, tag, protocol, settings)
	if err != nil {
		_ = h.repo.CancelUserManagedNodeCreation(r.Context(), creation.ID)
		writeManagedError(w, err)
		return
	}
	copyManagedCredentialOptions(protocol, settings, credential)
	if err := replaceInboundCredential(settings, protocol, credential); err != nil {
		_ = h.repo.DeleteUserInboundConfig(r.Context(), username, serverID, tag)
		_ = h.repo.CancelUserManagedNodeCreation(r.Context(), creation.ID)
		writeManagedError(w, err)
		return
	}
	cfg, err := h.repo.GetUserInboundConfig(r.Context(), username, serverID, tag)
	if err != nil {
		_ = h.repo.CancelUserManagedNodeCreation(r.Context(), creation.ID)
		writeManagedError(w, err)
		return
	}
	cleanupSource, err := h.repo.PreparePackageInboundCredentialCleanup(r.Context(), *cfg, "user-managed-create")
	if err != nil {
		_ = h.repo.DeleteUserInboundConfig(r.Context(), username, serverID, tag)
		_ = h.repo.CancelUserManagedNodeCreation(r.Context(), creation.ID)
		writeManagedError(w, err)
		return
	}
	if err := h.limiter.PushToServerChecked(r.Context(), serverID); err != nil {
		_ = h.cleanupFailedUserManagedCreation(r, creation, server, nil, nil, cleanupSource.ID, cfg.ID)
		writeJSONError(w, http.StatusServiceUnavailable, "failed to install deny-first limiter policy")
		return
	}
	applyManagedRealityCompatibility(request)
	if err := h.validateUserManagedNodeProfile(grant, inbound, server, username+"__"+tag); err != nil {
		_ = h.cleanupFailedUserManagedCreation(r, creation, server, nil, nil, cleanupSource.ID, cfg.ID)
		writeManagedError(w, err)
		return
	}
	normalized, _ := json.Marshal(request)
	forwardRequest := r.Clone(r.Context())
	forwardContext := withManagedNodeMutationID(forwardRequest.Context(), creation.MutationID)
	forwardContext = withManagedNodeOwner(forwardContext, username)
	forwardRequest = forwardRequest.WithContext(forwardContext)
	forwardRequest.Body = io.NopCloser(bytes.NewReader(normalized))
	forwardRequest.ContentLength = int64(len(normalized))
	recorder := &managedNodeResponseRecorder{header: make(http.Header)}
	h.remoteManage.HandleCreateManagedNode(recorder, forwardRequest)
	if recorder.status >= http.StatusBadRequest {
		_, _ = h.repo.MarkUserManagedNodeCreationDeleting(r.Context(), creation.ID,
			managedNodeResponseMessage(recorder, "remote creation result is uncertain"))
		copyHTTPResponse(w, recorder)
		return
	}
	var createdResponse struct {
		Success bool  `json:"success"`
		NodeID  int64 `json:"node_id"`
	}
	if json.Unmarshal(recorder.body.Bytes(), &createdResponse) != nil || !createdResponse.Success || createdResponse.NodeID <= 0 {
		_, _ = h.repo.MarkUserManagedNodeCreationDeleting(r.Context(), creation.ID, "managed node creation returned an invalid result")
		writeJSONError(w, http.StatusBadGateway, "managed node creation returned an invalid result")
		return
	}
	node, err := h.repo.GetNodeByID(r.Context(), createdResponse.NodeID)
	if err != nil {
		_, _ = h.repo.MarkUserManagedNodeCreationDeleting(r.Context(), creation.ID, "created node ownership could not be confirmed")
		writeManagedError(w, err)
		return
	}
	if node.Username != username || node.OriginalServer != server.Name || node.InboundTag != tag ||
		node.InboundMutationID != creation.MutationID || !grant.AllowsNodeProtocol(node.Protocol, node.ClashConfig) {
		_ = h.cleanupFailedUserManagedCreation(r, creation, server, &node, nil, cleanupSource.ID, cfg.ID)
		writeManagedError(w, storage.ErrManagedServerMismatch)
		return
	}
	offer, err := h.repo.CreatePrivateSelfServiceNodeOffer(r.Context(), node.ID, *grant, username)
	if err != nil {
		_ = h.cleanupFailedUserManagedCreation(r, creation, server, &node, nil, cleanupSource.ID, cfg.ID)
		writeManagedError(w, err)
		return
	}
	activation, err := h.repo.ActivateUserNodeSelection(r.Context(), username, offer.ID, username, time.Now().UTC())
	if err != nil {
		_ = h.repo.DeleteSelfServiceNodeOffer(r.Context(), offer.ID)
		_ = h.cleanupFailedUserManagedCreation(r, creation, server, &node, nil, cleanupSource.ID, cfg.ID)
		writeManagedError(w, err)
		return
	}
	if _, err := h.repo.PromoteUserManagedNodeCreation(r.Context(), creation.ID, node.ID, offer.ID,
		activation.Selection.ID, cleanupSource.ID, cfg.ID); err != nil {
		_ = h.cleanupFailedUserManagedCreation(r, creation, server, &node, &activation.Selection, cleanupSource.ID, cfg.ID)
		writeManagedError(w, err)
		return
	}
	if err := h.reconcileSource(r.Context(), activation.Source); err != nil {
		_ = h.cleanupFailedUserManagedCreation(r, creation, server, &node, &activation.Selection, 0, cfg.ID)
		writeJSONError(w, http.StatusServiceUnavailable, "managed node policy activation failed; creation was rolled back")
		return
	}
	current, _ := h.repo.GetUserManagedNodeCreation(r.Context(), creation.ID)
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"success": true, "message": "受管节点已创建", "node_id": node.ID,
		"node": convertNode(node), "creation": current,
	})
}

func (h *ManagedNodesHandler) HandleUserManagedNodeCreation(w http.ResponseWriter, r *http.Request) {
	username, ok := h.requireActiveManagedUser(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		payload, err := h.userManagedCreationContext(r.Context(), username)
		if err != nil {
			writeManagedError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, payload)
	case http.MethodPost:
		h.createUserManagedNode(w, r, username)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (h *ManagedNodesHandler) collectUserManagedRealityDomainCandidates(ctx context.Context, serverID int64) ([]string, error) {
	if h.remoteManage == nil {
		return nil, errors.New("managed node creation is unavailable")
	}
	server, err := h.repo.GetRemoteServer(ctx, serverID)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(strings.TrimSpace(server.XrayMode), "embedded") {
		return nil, storage.ErrManagedServerMismatch
	}
	seen := make(map[string]struct{})
	rawCandidates := make([]string, 0, 32)
	appendCandidate := func(raw string) {
		for _, value := range strings.Split(raw, ",") {
			domain := normalizeDomainCandidate(value)
			if !validUserManagedDomain(domain) {
				continue
			}
			if _, exists := seen[domain]; exists {
				continue
			}
			seen[domain] = struct{}{}
			rawCandidates = append(rawCandidates, domain)
		}
	}
	appendCandidate(server.Domain)
	appendCandidate(server.PullAddress)
	if raw, settingErr := h.repo.GetSystemSetting(ctx, "reality_domains"); settingErr == nil && strings.TrimSpace(raw) != "" {
		var configured []string
		if json.Unmarshal([]byte(raw), &configured) == nil {
			for _, domain := range configured {
				appendCandidate(domain)
			}
		}
	}

	// Only inspect the selected authorized server. The admin collector walks all
	// servers and would expose unrelated server domains through this user route.
	body, fetchErr := h.remoteManage.forwardToRemoteServer(ctx, serverID, http.MethodGet, "/api/child/inbounds", nil)
	if fetchErr == nil {
		var response struct {
			Success  bool                     `json:"success"`
			Inbounds []map[string]interface{} `json:"inbounds"`
		}
		if json.Unmarshal(body, &response) == nil && response.Success {
			extracted := make([]string, 0, len(response.Inbounds))
			extractedSeen := make(map[string]struct{})
			for _, inbound := range response.Inbounds {
				extractDomainsFromInbound(inbound, extractedSeen, &extracted)
			}
			for _, domain := range extracted {
				appendCandidate(domain)
			}
		}
	}

	resolver := h.realityResolver
	if resolver == nil {
		resolver = validatePublicUserManagedRealityDomain
	}
	candidates := make([]string, 0, len(rawCandidates))
	for _, domain := range rawCandidates {
		if err := resolver(ctx, domain); err == nil {
			candidates = append(candidates, domain)
		}
		if len(candidates) == 64 {
			break
		}
	}
	sort.Strings(candidates)
	return candidates, nil
}

func (h *ManagedNodesHandler) probeUserManagedRealityDomains(ctx context.Context, serverID int64, candidates []string, timeoutMs int) ([]realityDomainLatencyProbeResult, error) {
	if h.remoteManage == nil {
		return nil, errors.New("managed node creation is unavailable")
	}
	var results []realityDomainLatencyProbeResult
	if h.remoteManage.wsHandler != nil {
		if connection, connected := h.remoteManage.wsHandler.GetConnectionByServerID(serverID); connected && connection.Conn != nil {
			wsResult, err := h.remoteManage.wsHandler.SendDomainLatencyProbe(serverID, candidates, timeoutMs)
			if err == nil && wsResult != nil && wsResult.Success {
				for _, item := range wsResult.Results {
					results = append(results, realityDomainLatencyProbeResult{
						Domain: item.Domain, Target: item.Target, Success: item.Success,
						LatencyMs: item.LatencyMs, Error: item.Error, NginxSSLPort: int(item.NginxSSLPort),
					})
				}
			}
		}
	}
	if len(results) == 0 {
		body, err := json.Marshal(realityDomainLatencyProbeRequest{Domains: candidates, TimeoutMs: timeoutMs})
		if err != nil {
			return nil, err
		}
		body, err = h.remoteManage.forwardToRemoteServer(ctx, serverID, http.MethodPost, "/api/child/domains/latency", body)
		if err != nil {
			return nil, err
		}
		var response realityDomainLatencyProbeResponse
		if err := json.Unmarshal(body, &response); err != nil {
			return nil, fmt.Errorf("invalid domain probe response: %w", err)
		}
		if !response.Success {
			message := strings.TrimSpace(response.Error)
			if message == "" {
				message = "domain probe failed"
			}
			return nil, errors.New(message)
		}
		results = response.Results
	}

	allowed := make(map[string]struct{}, len(candidates))
	for _, domain := range candidates {
		allowed[domain] = struct{}{}
	}
	sanitized := make([]realityDomainLatencyProbeResult, 0, len(results))
	seen := make(map[string]struct{}, len(results))
	for _, result := range results {
		domain := normalizeDomainCandidate(result.Domain)
		if _, ok := allowed[domain]; !ok {
			continue
		}
		if _, duplicate := seen[domain]; duplicate {
			continue
		}
		seen[domain] = struct{}{}
		result.Domain = domain
		result.Target = domain + ":443"
		sanitized = append(sanitized, result)
	}
	sort.Slice(sanitized, func(i, j int) bool {
		if sanitized[i].Success != sanitized[j].Success {
			return sanitized[i].Success
		}
		if sanitized[i].LatencyMs != sanitized[j].LatencyMs {
			return sanitized[i].LatencyMs < sanitized[j].LatencyMs
		}
		return sanitized[i].Domain < sanitized[j].Domain
	})
	return sanitized, nil
}

func (h *ManagedNodesHandler) HandleUserManagedNodeCreationRealityDomains(w http.ResponseWriter, r *http.Request) {
	username, ok := h.requireActiveManagedUser(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	serverID, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("server_id")), 10, 64)
	if err != nil || serverID <= 0 {
		writeManagedError(w, storage.ErrManagedInvalidArgument)
		return
	}
	if _, err := h.activeUserServerGrant(r.Context(), username, serverID); err != nil {
		writeManagedError(w, err)
		return
	}
	candidates, err := h.collectUserManagedRealityDomainCandidates(r.Context(), serverID)
	if err != nil {
		writeManagedError(w, err)
		return
	}
	timeoutMs := 2000
	if raw := strings.TrimSpace(r.URL.Query().Get("timeout_ms")); raw != "" {
		if parsed, parseErr := strconv.Atoi(raw); parseErr == nil {
			if parsed < 200 {
				parsed = 200
			}
			if parsed > 10000 {
				parsed = 10000
			}
			timeoutMs = parsed
		}
	}
	if len(candidates) == 0 {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"success": true, "probe_server_id": serverID, "total_candidates": 0,
			"domains": []realityDomainLatencyProbeResult{},
		})
		return
	}
	results, err := h.probeUserManagedRealityDomains(r.Context(), serverID, candidates, timeoutMs)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "selected server could not probe Reality domains")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "probe_server_id": serverID, "total_candidates": len(candidates),
		"domains": results,
	})
}

func (h *ManagedNodesHandler) HandleUserManagedNodeCreationX25519(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireActiveManagedUser(w, r); !ok {
		return
	}
	NewXrayKeyGeneratorHandler().GenerateX25519(w, r)
}

func (h *ManagedNodesHandler) HandleUserManagedNodeCreationItem(w http.ResponseWriter, r *http.Request) {
	username, ok := h.requireActiveManagedUser(w, r)
	if !ok {
		return
	}
	if r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	id, err := managedRequestID(r, "id")
	if err != nil {
		writeManagedError(w, err)
		return
	}
	creation, err := h.repo.GetUserManagedNodeCreation(r.Context(), id)
	if err != nil || creation.Username != username {
		writeManagedError(w, storage.ErrUserManagedNodeCreationNotFound)
		return
	}
	if err := h.cleanupUserManagedNodeCreation(r.Context(), *creation, username); err != nil {
		writeJSON(w, http.StatusAccepted, map[string]interface{}{
			"success": true, "pending": true, "message": "远程删除尚未确认，系统将继续重试",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "pending": false})
}

func (h *ManagedNodesHandler) cleanupUserManagedNodeCreation(ctx context.Context, creation storage.UserManagedNodeCreation, actor string) error {
	leasedCtx, releaseAuthorization, err := h.repo.AcquireUserAuthorizationLease(ctx, creation.Username)
	if err != nil {
		return err
	}
	defer releaseAuthorization()
	current, err := h.repo.GetUserManagedNodeCreation(leasedCtx, creation.ID)
	if err != nil {
		return err
	}
	if current.Username != creation.Username || current.ServerID != creation.ServerID ||
		current.GrantID != creation.GrantID || current.InboundTag != creation.InboundTag ||
		current.MutationID != creation.MutationID {
		return storage.ErrManagedVersionConflict
	}
	if current.State != storage.UserManagedNodeDeleting {
		current, err = h.repo.MarkUserManagedNodeCreationDeleting(leasedCtx, current.ID, "deletion requested by "+strings.TrimSpace(actor))
		if err != nil {
			return err
		}
	}
	creation = *current
	leasedCtx, releaseServer, err := h.repo.AcquireRemoteServerExclusiveMutationLease(leasedCtx, creation.ServerID)
	if err != nil {
		return err
	}
	defer releaseServer()
	return h.cleanupUserManagedNodeCreationLocked(leasedCtx, creation, actor)
}

type userManagedNodeSupersession uint8

const (
	userManagedNodeNotSuperseded userManagedNodeSupersession = iota
	userManagedNodeSupersededSafe
	userManagedNodeSupersededWithOldCredential
)

func userManagedInboundContainsCredential(inbound map[string]interface{}, cfg *storage.UserInboundConfig) (bool, error) {
	if inbound == nil || cfg == nil {
		return false, storage.ErrManagedInvalidArgument
	}
	var credential map[string]interface{}
	if err := json.Unmarshal([]byte(cfg.CredentialJSON), &credential); err != nil || credential == nil {
		return false, fmt.Errorf("decode user-managed credential: %w", storage.ErrManagedInvalidArgument)
	}
	settings, ok := inbound["settings"].(map[string]interface{})
	if !ok || settings == nil {
		return false, fmt.Errorf("inspect replacement inbound settings: %w", storage.ErrManagedInvalidArgument)
	}
	primaryKey := inboundCredentialPrimaryKey(cfg.Protocol)
	if primaryKey == "" {
		return false, fmt.Errorf("inspect replacement inbound credential: %w", storage.ErrManagedInvalidArgument)
	}
	if primary := nonEmptyCredentialValue(credential, primaryKey); primary != "" &&
		primary == nonEmptyCredentialValue(settings, primaryKey) {
		return true, nil
	}
	for _, listKey := range []string{"clients", "users", "accounts", "peers"} {
		raw, exists := settings[listKey]
		if !exists || raw == nil {
			continue
		}
		clients, ok := raw.([]interface{})
		if !ok {
			return false, fmt.Errorf("inspect replacement inbound settings.%s: %w", listKey, storage.ErrManagedInvalidArgument)
		}
		for _, rawClient := range clients {
			client, ok := rawClient.(map[string]interface{})
			if !ok || client == nil {
				return false, fmt.Errorf("inspect replacement inbound settings.%s client: %w", listKey, storage.ErrManagedInvalidArgument)
			}
			if sameInboundClientForAdd(client, credential, cfg.Protocol) {
				return true, nil
			}
		}
	}
	return false, nil
}

func (h *ManagedNodesHandler) userManagedNodeCreationSupersededLocked(ctx context.Context, creation storage.UserManagedNodeCreation, server *storage.RemoteServer) (userManagedNodeSupersession, error) {
	if server == nil {
		return userManagedNodeNotSuperseded, storage.ErrManagedInvalidArgument
	}
	desired, err := h.repo.GetDesiredInbound(ctx, creation.ServerID, creation.InboundTag)
	if err != nil {
		return userManagedNodeNotSuperseded, err
	}
	if desired == nil {
		return userManagedNodeNotSuperseded, nil
	}
	oldMutation := strings.TrimSpace(creation.MutationID)
	replacementMutation := strings.TrimSpace(desired.MutationID)
	if oldMutation == "" || replacementMutation == "" || replacementMutation == oldMutation {
		return userManagedNodeNotSuperseded, nil
	}
	observed, fenceKnown, observedOwner, inventoryErr := h.remoteManage.managedInboundOwnershipFromAgent(
		ctx, creation.ServerID, creation.InboundTag,
	)
	if inventoryErr != nil {
		// Inventory uncertainty is not an error that permits local retirement.
		// Fall back to the normal deny + fenced cleanup path, which retains the
		// durable row if it cannot prove the old remote generation absent.
		return userManagedNodeNotSuperseded, nil
	}
	if !fenceKnown {
		return userManagedNodeNotSuperseded, nil
	}
	if desired.DesiredState == storage.DesiredInboundStateDeleted {
		if observed == nil && observedOwner == "" {
			return userManagedNodeSupersededSafe, nil
		}
		return userManagedNodeNotSuperseded, nil
	}
	observedFenceKnown, _ := observed["_mutation_fence_known"].(bool)
	observedMutation := strings.TrimSpace(wireGuardStringValue(observed["_mutation_id"]))
	if desired.DesiredState != storage.DesiredInboundStateActive || observed == nil || !observedFenceKnown ||
		observedMutation != replacementMutation || observedOwner != replacementMutation {
		return userManagedNodeNotSuperseded, nil
	}
	owner, err := h.repo.GetRemoteInboundOwnership(ctx, creation.ServerID, creation.InboundTag)
	if err != nil || strings.TrimSpace(owner) != replacementMutation {
		return userManagedNodeNotSuperseded, err
	}
	replacementOwner := h.repo.GetSystemNodeOwner(ctx)
	replacementNodes, err := h.repo.ListNodes(ctx, replacementOwner)
	if err != nil {
		return userManagedNodeNotSuperseded, err
	}
	replacementNodeFound := false
	for _, node := range replacementNodes {
		if node.OriginalServer == server.Name && node.InboundTag == creation.InboundTag &&
			strings.TrimSpace(node.InboundMutationID) == replacementMutation {
			replacementNodeFound = true
			break
		}
	}
	if !replacementNodeFound {
		// Agent acknowledgement can precede the EventInboundAdded/NodeSync
		// transaction. Retiring the old graph in that window would leave a live
		// inbound with no node row for UI, subscription, or Telegram queries.
		return userManagedNodeNotSuperseded, nil
	}
	cfg, err := h.repo.GetUserInboundConfig(ctx, creation.Username, creation.ServerID, creation.InboundTag)
	if err != nil {
		return userManagedNodeNotSuperseded, err
	}
	retained, err := userManagedInboundContainsCredential(observed, cfg)
	if err != nil {
		return userManagedNodeNotSuperseded, err
	}
	if retained {
		return userManagedNodeSupersededWithOldCredential, nil
	}
	return userManagedNodeSupersededSafe, nil
}

func (h *ManagedNodesHandler) prepareSupersededUserManagedNodeCreationLocked(ctx context.Context, creation storage.UserManagedNodeCreation, actor string, settleSource bool) error {
	if h.limiter == nil {
		return errors.New("limiter pusher is not available for superseded inbound cleanup")
	}
	if creation.SelectionID != nil {
		selection, err := h.repo.GetUserNodeSelectionForUser(ctx, *creation.SelectionID, creation.Username)
		if err == nil {
			result, deactivateErr := h.repo.DeactivateUserNodeSelection(ctx, creation.Username,
				selection.ID, actor, storage.ManagedSuspendAdminDisabled, time.Now().UTC())
			if deactivateErr != nil {
				return deactivateErr
			}
			// Publish the local inactive state as deny, but deliberately do not call
			// reconcileSource: its remove-client action would target the replacement
			// administrator generation that this creation does not own.
			if denyErr := h.limiter.PushToServerChecked(ctx, creation.ServerID); denyErr != nil {
				return denyErr
			}
			if settleSource {
				if _, applyErr := h.repo.MarkUserInboundAccessSourceApplied(ctx, result.Source.ID,
					result.Source.Generation, storage.ManagedObservedInactive, time.Now().UTC()); applyErr != nil {
					return applyErr
				}
			}
		} else if !errors.Is(err, storage.ErrUserNodeSelectionNotFound) {
			return err
		}
	} else if err := h.limiter.PushToServerChecked(ctx, creation.ServerID); err != nil {
		// A pre-promotion creation already owns an inactive legacy source. Keep its
		// deny acknowledged until the local graph and credential are gone.
		return err
	}
	return nil
}

func (h *ManagedNodesHandler) cleanupSupersededUserManagedNodeCreationLocked(ctx context.Context, creation storage.UserManagedNodeCreation, server *storage.RemoteServer, actor string) error {
	if err := h.prepareSupersededUserManagedNodeCreationLocked(ctx, creation, actor, true); err != nil {
		return err
	}
	if err := h.repo.DeleteSupersededUserManagedNodeCreationGraph(ctx, creation.ID,
		server.Name, creation.MutationID); err != nil {
		return err
	}
	if err := h.limiter.PushToServerChecked(ctx, creation.ServerID); err != nil {
		// The old credential is gone; retaining a stale deny is fail-closed.
		return nil
	}
	return nil
}

func (h *ManagedNodesHandler) userManagedNodeCreationHasIndependentAccess(ctx context.Context, creation storage.UserManagedNodeCreation) (bool, error) {
	excludeSourceID := int64(0)
	if creation.SelectionID != nil {
		selection, err := h.repo.GetUserNodeSelectionForUser(ctx, *creation.SelectionID, creation.Username)
		switch {
		case err == nil && selection.AccessSourceID != nil:
			excludeSourceID = *selection.AccessSourceID
		case err != nil && !errors.Is(err, storage.ErrUserNodeSelectionNotFound):
			return false, err
		}
	}
	now := time.Now().UTC()
	hasManaged, _, err := h.repo.HasEffectiveUserInboundAccess(ctx, creation.Username,
		creation.ServerID, creation.InboundTag, excludeSourceID, now)
	if err != nil {
		return false, err
	}
	if hasManaged {
		return true, nil
	}
	hasDirect, _, err := h.repo.HasEffectiveDirectUserInboundAccess(ctx, creation.Username,
		creation.ServerID, creation.InboundTag, excludeSourceID, now)
	if err != nil {
		return false, err
	}
	return hasDirect, nil
}

func (h *ManagedNodesHandler) removeRetainedCredentialFromSupersededInboundLocked(ctx context.Context, creation storage.UserManagedNodeCreation, server *storage.RemoteServer, actor string) error {
	cfg, err := h.repo.GetUserInboundConfig(ctx, creation.Username, creation.ServerID, creation.InboundTag)
	if err != nil {
		return err
	}
	hasIndependentAccess, err := h.userManagedNodeCreationHasIndependentAccess(ctx, creation)
	if err != nil {
		return err
	}
	if hasIndependentAccess {
		// The replacement still carries a credential that another active source
		// authorizes. Retire only this creation's private graph; removing the
		// client or its shared credential snapshot would revoke the independent
		// source and leave dangling credential_config_id links.
		return h.cleanupSupersededUserManagedNodeCreationLocked(ctx, creation, server, actor)
	}
	if err := h.prepareSupersededUserManagedNodeCreationLocked(ctx, creation, actor, false); err != nil {
		return err
	}
	var credential map[string]interface{}
	if err := json.Unmarshal([]byte(cfg.CredentialJSON), &credential); err != nil || credential == nil {
		return fmt.Errorf("decode retained user-managed credential: %w", storage.ErrManagedInvalidArgument)
	}
	desired, err := h.repo.GetDesiredInbound(ctx, creation.ServerID, creation.InboundTag)
	if err != nil {
		return err
	}
	if desired == nil || desired.DesiredState != storage.DesiredInboundStateActive ||
		strings.TrimSpace(desired.MutationID) == "" || strings.TrimSpace(desired.MutationID) == strings.TrimSpace(creation.MutationID) {
		return errors.New("replacement desired inbound generation is unavailable")
	}
	replacementMutation := strings.TrimSpace(desired.MutationID)
	inbound, err := decodeDesiredInbound(desired.InboundJSON)
	if err != nil {
		return fmt.Errorf("decode replacement desired inbound: %w", err)
	}
	protocol := canonicalManagedProtocol(wireGuardStringValue(inbound["protocol"]))
	if protocol == "" || protocol != canonicalManagedProtocol(cfg.Protocol) {
		return errors.New("replacement inbound protocol cannot safely remove the old credential")
	}
	settings, _ := inbound["settings"].(map[string]interface{})
	if settings == nil {
		return errors.New("replacement desired inbound has no settings object")
	}
	listKey, err := inboundClientListKey(protocol, settings)
	if err != nil {
		return fmt.Errorf("resolve replacement credential list: %w", err)
	}
	var clients []interface{}
	if raw, exists := settings[listKey]; exists && raw != nil {
		var ok bool
		clients, ok = raw.([]interface{})
		if !ok {
			return fmt.Errorf("replacement desired inbound has invalid %s list", listKey)
		}
	}
	clients = filterCredentials(clients, credential, protocol)
	if clients == nil {
		clients = make([]interface{}, 0)
	}
	settings[listKey] = clients
	inboundJSON, err := json.Marshal(inbound)
	if err != nil {
		return fmt.Errorf("encode replacement desired inbound: %w", err)
	}
	if _, err := h.repo.UpsertActiveDesiredInbound(ctx, creation.ServerID, creation.InboundTag,
		replacementMutation, inboundJSON); err != nil {
		return fmt.Errorf("remove old credential from replacement desired inbound: %w", err)
	}
	if err := removeUserFromInbound(ctx, h.remoteManage, *cfg); err != nil {
		return err
	}
	observed, fenceKnown, observedOwner, err := h.remoteManage.managedInboundOwnershipFromAgent(
		ctx, creation.ServerID, creation.InboundTag,
	)
	if err != nil {
		return fmt.Errorf("confirm replacement credential removal: %w", err)
	}
	observedFenceKnown, _ := observed["_mutation_fence_known"].(bool)
	if !fenceKnown || observed == nil || !observedFenceKnown ||
		strings.TrimSpace(wireGuardStringValue(observed["_mutation_id"])) != replacementMutation || observedOwner != replacementMutation {
		return errors.New("replacement inbound generation changed while removing old credential")
	}
	retained, err := userManagedInboundContainsCredential(observed, cfg)
	if err != nil {
		return err
	}
	if retained {
		return errors.New("replacement inbound still contains the revoked user credential after Agent ACK")
	}
	return h.cleanupSupersededUserManagedNodeCreationLocked(ctx, creation, server, actor)
}

func (h *ManagedNodesHandler) cleanupUserManagedNodeCreationLocked(ctx context.Context, creation storage.UserManagedNodeCreation, actor string) error {
	if h.remoteManage == nil {
		return errors.New("remote manager is not available")
	}
	current, err := h.repo.RecoverUserManagedNodeCreationLinks(ctx, creation.ID)
	if err == nil {
		creation = *current
	}
	server, err := h.repo.GetRemoteServer(ctx, creation.ServerID)
	if err != nil {
		_, _ = h.repo.MarkUserManagedNodeCreationDeleting(ctx, creation.ID, err.Error())
		return err
	}
	mutationID := strings.TrimSpace(creation.MutationID)
	if mutationID == "" {
		err := errors.New("user-managed node ownership mutation is missing")
		_, _ = h.repo.MarkUserManagedNodeCreationDeleting(ctx, creation.ID, err.Error())
		return err
	}
	supersession, err := h.userManagedNodeCreationSupersededLocked(ctx, creation, server)
	if err != nil {
		_, _ = h.repo.MarkUserManagedNodeCreationDeleting(ctx, creation.ID, err.Error())
		return err
	}
	if supersession == userManagedNodeSupersededWithOldCredential {
		if err := h.removeRetainedCredentialFromSupersededInboundLocked(ctx, creation, server, actor); err != nil {
			_, _ = h.repo.MarkUserManagedNodeCreationDeleting(ctx, creation.ID, err.Error())
			return err
		}
		return nil
	}
	if supersession == userManagedNodeSupersededSafe {
		if err := h.cleanupSupersededUserManagedNodeCreationLocked(ctx, creation, server, actor); err != nil {
			_, _ = h.repo.MarkUserManagedNodeCreationDeleting(ctx, creation.ID, err.Error())
			return err
		}
		return nil
	}
	if creation.SelectionID != nil {
		selection, selectionErr := h.repo.GetUserNodeSelectionForUser(ctx, *creation.SelectionID, creation.Username)
		if selectionErr == nil {
			result, deactivateErr := h.repo.DeactivateUserNodeSelection(ctx, creation.Username,
				selection.ID, actor, storage.ManagedSuspendAdminDisabled, time.Now().UTC())
			if deactivateErr != nil {
				_, _ = h.repo.MarkUserManagedNodeCreationDeleting(ctx, creation.ID, deactivateErr.Error())
				return deactivateErr
			}
			if h.limiter == nil {
				err := errors.New("limiter pusher is not available for dedicated inbound cleanup")
				_, _ = h.repo.MarkUserManagedNodeCreationDeleting(ctx, creation.ID, err.Error())
				return err
			}
			// This dedicated inbound may have just attempted a normal policy
			// publish. Require an explicit deny replacement before any client or
			// whole-inbound removal, so a later remote failure cannot expose it.
			if denyErr := h.limiter.PushToServerChecked(ctx, creation.ServerID); denyErr != nil {
				_, _ = h.repo.MarkUserManagedNodeCreationDeleting(ctx, creation.ID, denyErr.Error())
				return denyErr
			}
			if reconcileErr := h.reconcileSource(ctx, result.Source); reconcileErr != nil {
				_, _ = h.repo.MarkUserManagedNodeCreationDeleting(ctx, creation.ID, reconcileErr.Error())
				return reconcileErr
			}
		} else if !errors.Is(selectionErr, storage.ErrUserNodeSelectionNotFound) {
			return selectionErr
		}
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/api/user/managed-node-creation", nil)
	if rollbackErr := h.remoteManage.rollbackManagedNode(request, creation.ServerID, server.Name,
		creation.InboundTag, mutationID); rollbackErr != nil {
		_, _ = h.repo.MarkUserManagedNodeCreationDeleting(ctx, creation.ID, rollbackErr.Error())
		return rollbackErr
	}
	err = h.repo.DeleteUserManagedNodeCreationGraph(ctx, creation.ID)
	if err != nil {
		_, _ = h.repo.MarkUserManagedNodeCreationDeleting(ctx, creation.ID, err.Error())
		return err
	}
	if h.limiter != nil {
		if err := h.limiter.PushToServerChecked(ctx, creation.ServerID); err != nil {
			// The credential and inbound are already absent. A stale restrictive
			// limiter entry is safe and the next normal publish will clear it.
			return nil
		}
	}
	return nil
}

func (h *ManagedNodesHandler) promoteRecoveredUserManagedNodeCreation(ctx context.Context, creation storage.UserManagedNodeCreation) (*storage.UserManagedNodeCreation, error) {
	if creation.NodeID == nil || creation.OfferID == nil || creation.SelectionID == nil {
		return nil, storage.ErrManagedResourceInUse
	}
	credential, err := h.repo.GetUserInboundConfig(ctx, creation.Username, creation.ServerID, creation.InboundTag)
	if err != nil {
		return nil, err
	}
	sources, err := h.repo.ListUserInboundAccessSources(ctx, creation.Username, creation.ServerID)
	if err != nil {
		return nil, err
	}
	var cleanupSourceID int64
	for _, source := range sources {
		if source.SourceType == storage.ManagedSourceLegacyReview && source.SourceID == credential.ID &&
			source.InboundTag == creation.InboundTag && source.DesiredState == storage.ManagedDesiredInactive {
			cleanupSourceID = source.ID
			break
		}
	}
	if cleanupSourceID == 0 {
		return nil, storage.ErrManagedAccessSourceNotFound
	}
	return h.repo.PromoteUserManagedNodeCreation(ctx, creation.ID, *creation.NodeID, *creation.OfferID,
		*creation.SelectionID, cleanupSourceID, credential.ID)
}

func (h *ManagedNodesHandler) recoverAndPromoteUserManagedNodeCreation(ctx context.Context, expected storage.UserManagedNodeCreation) (*storage.UserManagedNodeCreation, error) {
	leasedCtx, releaseAuthorization, err := h.repo.AcquireUserAuthorizationLease(ctx, expected.Username)
	if err != nil {
		return nil, err
	}
	defer releaseAuthorization()
	leasedCtx, releaseServer, err := h.repo.AcquireRemoteServerExclusiveMutationLease(leasedCtx, expected.ServerID)
	if err != nil {
		return nil, err
	}
	defer releaseServer()
	current, err := h.repo.GetUserManagedNodeCreation(leasedCtx, expected.ID)
	if err != nil {
		return nil, err
	}
	if current.Username != expected.Username || current.ServerID != expected.ServerID ||
		current.GrantID != expected.GrantID || current.InboundTag != expected.InboundTag ||
		current.MutationID != expected.MutationID || current.State != storage.UserManagedNodeCreating {
		return current, storage.ErrManagedVersionConflict
	}
	current, err = h.repo.RecoverUserManagedNodeCreationLinks(leasedCtx, current.ID)
	if err != nil || current.NodeID == nil || current.OfferID == nil || current.SelectionID == nil {
		if err == nil {
			err = storage.ErrManagedResourceInUse
		}
		return current, err
	}
	grant, err := h.activeUserServerGrant(leasedCtx, current.Username, current.ServerID)
	if err != nil || grant.ID != current.GrantID {
		if err == nil {
			err = storage.ErrManagedGrantInactive
		}
		return current, err
	}
	node, err := h.repo.GetNodeByID(leasedCtx, *current.NodeID)
	if err != nil || node.Username != current.Username || node.InboundTag != current.InboundTag ||
		node.InboundMutationID != current.MutationID || !grant.AllowsNodeProtocol(node.Protocol, node.ClashConfig) ||
		!storage.SelfServiceNodeProtocolEligible(node.Protocol, node.ClashConfig) {
		if err == nil {
			err = storage.ErrManagedServerMismatch
		}
		return current, err
	}
	selection, err := h.repo.GetUserNodeSelectionForUser(leasedCtx, *current.SelectionID, current.Username)
	if err != nil || !selection.DesiredEnabled || selection.GrantID != current.GrantID ||
		selection.OfferID != *current.OfferID || selection.AccessSourceID == nil {
		if err == nil {
			err = storage.ErrManagedServerMismatch
		}
		deleting, markErr := h.repo.MarkUserManagedNodeCreationDeleting(leasedCtx, current.ID, "recovered selection is no longer active")
		if markErr != nil {
			return current, errors.Join(err, markErr)
		}
		return deleting, err
	}
	source, err := h.repo.GetUserInboundAccessSource(leasedCtx, *selection.AccessSourceID)
	if err != nil || source.SourceType != storage.ManagedSourceSelection || source.SourceID != selection.ID ||
		source.Username != current.Username || source.ServerID != current.ServerID ||
		source.InboundTag != current.InboundTag || source.NodeID != node.ID ||
		source.DesiredState != storage.ManagedDesiredActive {
		if err == nil {
			err = storage.ErrManagedServerMismatch
		}
		deleting, markErr := h.repo.MarkUserManagedNodeCreationDeleting(leasedCtx, current.ID, "recovered selection policy is no longer active")
		if markErr != nil {
			return current, errors.Join(err, markErr)
		}
		return deleting, err
	}
	return h.promoteRecoveredUserManagedNodeCreation(leasedCtx, *current)
}

func userManagedCreationGrantInvalid(err error) bool {
	return errors.Is(err, storage.ErrUserServerGrantNotFound) ||
		errors.Is(err, storage.ErrUserNotFound) ||
		errors.Is(err, storage.ErrManagedGrantInactive) ||
		errors.Is(err, storage.ErrManagedTrafficLimit)
}

func (h *ManagedNodesHandler) userManagedNodeCreationMustDeleteLocked(ctx context.Context, creation storage.UserManagedNodeCreation, now time.Time) (bool, error) {
	if creation.State == storage.UserManagedNodeDeleting {
		return true, nil
	}
	if creation.State != storage.UserManagedNodeCreating && creation.State != storage.UserManagedNodeActive {
		return true, nil
	}
	if creation.State == storage.UserManagedNodeCreating && now.Sub(creation.UpdatedAt) >= 2*time.Minute {
		return true, nil
	}
	grant, err := h.activeUserServerGrant(ctx, creation.Username, creation.ServerID)
	if err != nil {
		if userManagedCreationGrantInvalid(err) {
			return true, nil
		}
		return false, err
	}
	if grant.ID != creation.GrantID {
		return true, nil
	}
	if creation.NodeID == nil {
		return creation.State == storage.UserManagedNodeActive, nil
	}
	node, err := h.repo.GetNodeByID(ctx, *creation.NodeID)
	if err != nil {
		if errors.Is(err, storage.ErrNodeNotFound) {
			return true, nil
		}
		return false, err
	}
	server, err := h.repo.GetRemoteServer(ctx, creation.ServerID)
	if err != nil {
		if errors.Is(err, storage.ErrRemoteServerNotFound) {
			return true, nil
		}
		return false, err
	}
	if supersession, supersededErr := h.userManagedNodeCreationSupersededLocked(ctx, creation, server); supersededErr != nil {
		return false, supersededErr
	} else if supersession != userManagedNodeNotSuperseded {
		return true, nil
	}
	return node.Username != creation.Username || node.OriginalServer != server.Name ||
		node.InboundTag != creation.InboundTag || node.InboundMutationID != creation.MutationID ||
		!grant.AllowsNodeProtocol(node.Protocol, node.ClashConfig) ||
		!storage.SelfServiceNodeProtocolEligible(node.Protocol, node.ClashConfig), nil
}

func (h *ManagedNodesHandler) cleanupUserManagedNodeCreationIfStillInvalid(ctx context.Context, expected storage.UserManagedNodeCreation, now time.Time, actor string) error {
	leasedCtx, releaseAuthorization, err := h.repo.AcquireUserAuthorizationLease(ctx, expected.Username)
	if err != nil {
		return err
	}
	defer releaseAuthorization()
	leasedCtx, releaseServer, err := h.repo.AcquireRemoteServerExclusiveMutationLease(leasedCtx, expected.ServerID)
	if err != nil {
		return err
	}
	defer releaseServer()
	current, err := h.repo.GetUserManagedNodeCreation(leasedCtx, expected.ID)
	if errors.Is(err, storage.ErrUserManagedNodeCreationNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if current.Username != expected.Username || current.ServerID != expected.ServerID ||
		current.GrantID != expected.GrantID || current.InboundTag != expected.InboundTag ||
		current.MutationID != expected.MutationID {
		return storage.ErrManagedVersionConflict
	}
	if recovered, recoverErr := h.repo.RecoverUserManagedNodeCreationLinks(leasedCtx, current.ID); recoverErr == nil {
		current = recovered
	} else {
		return recoverErr
	}
	mustDelete, err := h.userManagedNodeCreationMustDeleteLocked(leasedCtx, *current, now)
	if err != nil || !mustDelete {
		return err
	}
	if current.State != storage.UserManagedNodeDeleting {
		current, err = h.repo.MarkUserManagedNodeCreationDeleting(leasedCtx, current.ID, "authorization or managed ownership is no longer valid")
		if err != nil {
			return err
		}
	}
	if strings.TrimSpace(actor) == "" {
		actor = "reconciler"
	}
	return h.cleanupUserManagedNodeCreationLocked(leasedCtx, *current, actor)
}
