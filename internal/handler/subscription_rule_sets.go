package handler

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/violetaini/relaydock/internal/safefetch"
)

type subscriptionRuleSetCache struct {
	sync.Mutex
	content []byte
	updated time.Time
	retryAt time.Time
}
type subscriptionRuleSetsHandler struct {
	client  *http.Client
	entries map[string]*subscriptionRuleSetCache
}

// This public endpoint only serves whitelisted public rule data. Node data,
// user credentials and caller-supplied URLs never enter the rule-set cache.
func NewSubscriptionRuleSetsHandler() http.Handler {
	entries := map[string]*subscriptionRuleSetCache{}
	for _, category := range subscriptionRuleCategories {
		for _, rule := range category.Rules {
			parts := strings.Split(rule, ",")
			entries[strings.ToLower(parts[0])+"/"+strings.ToLower(parts[1])+".list"] = &subscriptionRuleSetCache{}
		}
	}
	return &subscriptionRuleSetsHandler{client: safefetch.NewClient(20*time.Second, 6<<20), entries: entries}
}

func (h *subscriptionRuleSetsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w, http.MethodGet, http.MethodHead)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, subscriptionRuleSetPrefix)
	entry, ok := h.entries[key]
	if !ok {
		http.NotFound(w, r)
		return
	}
	entry.Lock()
	if (len(entry.content) == 0 || time.Since(entry.updated) > 24*time.Hour) && time.Now().After(entry.retryAt) {
		body, err := h.fetch(r, key)
		if err == nil {
			entry.content, entry.updated = body, time.Now()
		} else {
			entry.retryAt = time.Now().Add(5 * time.Minute)
		}
	}
	if len(entry.content) == 0 || time.Since(entry.updated) > 7*24*time.Hour {
		entry.Unlock()
		http.Error(w, "分类规则暂不可用，请稍后重试", http.StatusBadGateway)
		return
	}
	if time.Since(entry.updated) > 24*time.Hour {
		w.Header().Set("Warning", `110 - "Serving cached rule set"`)
	}
	body := entry.content
	entry.Unlock()
	etag := fmt.Sprintf(`"%x"`, sha256.Sum256(body))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

func (h *subscriptionRuleSetsHandler) fetch(r *http.Request, key string) ([]byte, error) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/"+key, nil)
	if err != nil {
		return nil, err
	}
	res, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("upstream status %d", res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, (6<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 6<<20 {
		return nil, fmt.Errorf("rule set too large")
	}
	return convertPublicSubscriptionRuleSet(raw, strings.HasPrefix(key, "geoip/"))
}

func convertPublicSubscriptionRuleSet(raw []byte, ipRules bool) ([]byte, error) {
	var result bytes.Buffer
	scan := bufio.NewScanner(bytes.NewReader(raw))
	scan.Buffer(make([]byte, 4096), 16384)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if ipRules {
			ip, _, err := net.ParseCIDR(line)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR rule")
			}
			kind := "IP-CIDR"
			if ip.To4() == nil {
				kind = "IP-CIDR6"
			}
			fmt.Fprintf(&result, "%s,%s,no-resolve\n", kind, line)
		} else {
			kind := "DOMAIN"
			if strings.HasPrefix(line, "+.") {
				kind = "DOMAIN-SUFFIX"
				line = strings.TrimPrefix(line, "+.")
			}
			if line == "" || strings.ContainsAny(line, ", \t\r\n*:") {
				return nil, fmt.Errorf("unsupported domain rule")
			}
			fmt.Fprintf(&result, "%s,%s\n", kind, line)
		}
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}
	if result.Len() == 0 {
		return nil, fmt.Errorf("empty rule set")
	}
	return result.Bytes(), nil
}
