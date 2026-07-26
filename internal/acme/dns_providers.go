package acme

import (
	"fmt"
	"os"
	"sync"

	"miaomiaowux/internal/dnscredentials"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/alidns"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/dnspod"
	"github.com/go-acme/lego/v4/providers/dns/godaddy"
	"github.com/go-acme/lego/v4/providers/dns/namesilo"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
)

// 支持的 DNS 提供商类型及其所需的环境变量映射。
var DNSProviderEnvKeys = map[string][]string{
	"cloudflare":   {"CF_API_EMAIL", "CF_API_KEY", "CF_DNS_API_TOKEN"},
	"alidns":       {"ALICLOUD_ACCESS_KEY", "ALICLOUD_SECRET_KEY"},
	"tencentcloud": {"TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY"},
	"dnspod":       {"DNSPOD_API_KEY"},
	"namesilo":     {"NAMESILO_API_KEY"},
	"godaddy":      {"GODADDY_API_KEY", "GODADDY_API_SECRET"},
}

var dnsCredentialEnvMu sync.Mutex

// NewDNSProviderByName 按名称创建 DNS 质询提供程序。
// 仅导入我们支持的特定提供程序以避免依赖膨胀。
func NewDNSProviderByName(name string) (challenge.Provider, error) {
	switch name {
	case "cloudflare":
		return cloudflare.NewDNSProvider()
	case "alidns":
		return alidns.NewDNSProvider()
	case "tencentcloud":
		return tencentcloud.NewDNSProvider()
	case "dnspod":
		return dnspod.NewDNSProvider()
	case "namesilo":
		return namesilo.NewDNSProvider()
	case "godaddy":
		return godaddy.NewDNSProvider()
	default:
		return nil, fmt.Errorf("unsupported DNS provider: %s", name)
	}
}

// SetDNSCredentialEnv 从给定提供程序的凭据映射中设置环境变量。
// 返回一个清除变量的清理函数。
func SetDNSCredentialEnv(providerType string, credentials map[string]string) (cleanup func(), err error) {
	keys, ok := DNSProviderEnvKeys[providerType]
	if !ok {
		return nil, fmt.Errorf("unsupported DNS provider type: %s", providerType)
	}
	if providerType == "cloudflare" {
		credentials, err = dnscredentials.NormalizeCloudflare(credentials)
		if err != nil {
			return nil, err
		}
	}

	// lego providers read process environment variables during construction.
	// Serialize this short setup window and restore the caller's environment so
	// credentials from another mode/request cannot influence authentication.
	dnsCredentialEnvMu.Lock()
	type previousValue struct {
		value  string
		exists bool
	}
	previous := make(map[string]previousValue, len(keys))
	for _, key := range keys {
		value, exists := os.LookupEnv(key)
		previous[key] = previousValue{value: value, exists: exists}
		_ = os.Unsetenv(key)
	}
	restore := func() {
		for _, key := range keys {
			old := previous[key]
			if old.exists {
				_ = os.Setenv(key, old.value)
			} else {
				_ = os.Unsetenv(key)
			}
		}
		dnsCredentialEnvMu.Unlock()
	}

	var setKeys []string
	for _, key := range keys {
		if val, exists := credentials[key]; exists && val != "" {
			if err := os.Setenv(key, val); err != nil {
				restore()
				return nil, fmt.Errorf("set DNS credential %s: %w", key, err)
			}
			setKeys = append(setKeys, key)
		}
	}

	if len(setKeys) == 0 {
		restore()
		return nil, fmt.Errorf("no valid credentials provided for DNS provider %s", providerType)
	}

	var once sync.Once
	cleanup = func() {
		once.Do(restore)
	}
	return cleanup, nil
}

// CA 目录 URL 常量
const (
	CALetsEncrypt        = "letsencrypt"
	CALetsEncryptStaging = "letsencrypt-staging"
)

var CADirectoryURLs = map[string]string{
	CALetsEncrypt:        "https://acme-v02.api.letsencrypt.org/directory",
	CALetsEncryptStaging: "https://acme-staging-v02.api.letsencrypt.org/directory",
}

// 返回给定提供程序名称的 ACME 目录 URL。
func ResolveCADirectoryURL(provider string, staging bool) string {
	if staging {
		if url, ok := CADirectoryURLs[provider+"-staging"]; ok {
			return url
		}
		if url, ok := CADirectoryURLs[provider+"-test"]; ok {
			return url
		}
		return CADirectoryURLs[CALetsEncryptStaging]
	}
	if url, ok := CADirectoryURLs[provider]; ok {
		return url
	}
	return CADirectoryURLs[CALetsEncrypt]
}
