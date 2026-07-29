package ddns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/dnscredentials"
)

// cloudflareProvider 直接调 CF v4 HTTP API,不依赖 lego internal 包(lego 的 cloudflare client 在
// internal/ 下,Go 规则下外部包不可 import)。
//
// 凭据 JSON key 沿用 acme/dns_providers.go 的 env var 名:
//   - CF_DNS_API_TOKEN(推荐,scoped token)
//   - 或 CF_API_EMAIL + CF_API_KEY(legacy Global Key)
type cloudflareProvider struct {
	httpClient *http.Client
	baseURL    string // 单测注入用
	authHeader func(req *http.Request)

	zoneCache sync.Map // map[string]string,key=root zone domain,val=zone_id
}

func newCloudflareProvider(creds map[string]string) (*cloudflareProvider, error) {
	auth, err := dnscredentials.ResolveCloudflare(creds)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: %w", err)
	}

	return &cloudflareProvider{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		baseURL:    "https://api.cloudflare.com/client/v4",
		authHeader: auth.Apply,
	}, nil
}

// cfResponse — CF API 统一响应结构
type cfResponse struct {
	Success bool            `json:"success"`
	Errors  []cfError       `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	TTL     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
}

func (p *cloudflareProvider) UpsertRecord(ctx context.Context, fqdn string, recordType string, content string, ttl int) error {
	zone, _, err := SplitFQDN(fqdn)
	if err != nil {
		return fmt.Errorf("split fqdn: %w", err)
	}
	zoneID, err := p.resolveZoneID(ctx, zone)
	if err != nil {
		return err
	}
	existing, err := p.findRecord(ctx, zoneID, fqdn, recordType)
	if err != nil {
		return err
	}
	if ttl == 0 {
		ttl = 120
	}
	if existing != nil {
		if existing.Content == content && existing.TTL == ttl {
			return nil // 已经是想要的状态,跳过
		}
		return p.updateRecord(ctx, zoneID, existing.ID, recordType, fqdn, content, ttl)
	}
	return p.createRecord(ctx, zoneID, recordType, fqdn, content, ttl)
}

func (p *cloudflareProvider) resolveZoneID(ctx context.Context, zoneName string) (string, error) {
	if v, ok := p.zoneCache.Load(zoneName); ok {
		return v.(string), nil
	}
	url := fmt.Sprintf("%s/zones?name=%s", p.baseURL, zoneName)
	var zones []cfZone
	if err := p.doJSON(ctx, http.MethodGet, url, nil, &zones); err != nil {
		return "", fmt.Errorf("list zones: %w", err)
	}
	if len(zones) == 0 {
		return "", fmt.Errorf("cloudflare zone %q not found (check token scope)", zoneName)
	}
	p.zoneCache.Store(zoneName, zones[0].ID)
	return zones[0].ID, nil
}

func (p *cloudflareProvider) findRecord(ctx context.Context, zoneID string, fqdn string, recordType string) (*cfDNSRecord, error) {
	url := fmt.Sprintf("%s/zones/%s/dns_records?type=%s&name=%s", p.baseURL, zoneID, recordType, fqdn)
	var records []cfDNSRecord
	if err := p.doJSON(ctx, http.MethodGet, url, nil, &records); err != nil {
		return nil, fmt.Errorf("list dns_records: %w", err)
	}
	if len(records) == 0 {
		return nil, nil
	}
	return &records[0], nil
}

func (p *cloudflareProvider) createRecord(ctx context.Context, zoneID, recordType, fqdn, content string, ttl int) error {
	url := fmt.Sprintf("%s/zones/%s/dns_records", p.baseURL, zoneID)
	body := map[string]interface{}{
		"type":    recordType,
		"name":    fqdn,
		"content": content,
		"ttl":     ttl,
		"proxied": false, // 关键:DDNS 必须直连,不能走橙云代理
	}
	return p.doJSON(ctx, http.MethodPost, url, body, nil)
}

func (p *cloudflareProvider) updateRecord(ctx context.Context, zoneID, recordID, recordType, fqdn, content string, ttl int) error {
	url := fmt.Sprintf("%s/zones/%s/dns_records/%s", p.baseURL, zoneID, recordID)
	body := map[string]interface{}{
		"type":    recordType,
		"name":    fqdn,
		"content": content,
		"ttl":     ttl,
		"proxied": false,
	}
	return p.doJSON(ctx, http.MethodPatch, url, body, nil)
}

// doJSON 发起 HTTP 请求,解析 CF 标准响应,把 Result 解码到 out(可为 nil)。
func (p *cloudflareProvider) doJSON(ctx context.Context, method, url string, body interface{}, out interface{}) error {
	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
		reqBody = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	p.authHeader(req)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	var cfResp cfResponse
	if err := json.Unmarshal(respBytes, &cfResp); err != nil {
		return fmt.Errorf("parse response (status=%d): %w; body=%s", resp.StatusCode, err, truncate(string(respBytes), 200))
	}
	if !cfResp.Success {
		var msgs []string
		for _, e := range cfResp.Errors {
			msgs = append(msgs, fmt.Sprintf("[%d] %s", e.Code, e.Message))
		}
		if len(msgs) == 0 {
			msgs = append(msgs, fmt.Sprintf("HTTP %d", resp.StatusCode))
		}
		return dnscredentials.FriendlyCloudflareError(fmt.Errorf("cloudflare API: %s", strings.Join(msgs, "; ")))
	}
	if out != nil && len(cfResp.Result) > 0 {
		if err := json.Unmarshal(cfResp.Result, out); err != nil {
			return fmt.Errorf("unmarshal result: %w", err)
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
