// Package mmwxclient 是内嵌 Bot 调用 Arcway 主控 API 的进程内客户端。
//
// 鉴权:Authorization: Bearer <internal token>(admin 级 token,bot 内部按 tg_id 分发权限)。
// 所有错误透传(网络/状态码/JSON 解析失败均返回 wrapped error)。
package mmwxclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"
)

type Client struct {
	baseURL    string
	apiToken   string
	httpClient *http.Client
}

type handlerTransport struct{ handler http.Handler }

func (t handlerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	t.handler.ServeHTTP(recorder, req)
	return recorder.Result(), nil
}

// NewInProcess routes bot API calls directly through the master's mux. The
// token is an internal short-lived admin session and never leaves the process.
func NewInProcess(handler http.Handler, token string, timeoutSeconds int) *Client {
	c := New("http://arcway.internal", token, timeoutSeconds)
	c.httpClient.Transport = handlerTransport{handler: handler}
	return c
}

// New 构造 client。base 形如 "https://mmw.domain.com",token 是 admin api token。
func New(base, token string, timeoutSeconds int) *Client {
	if timeoutSeconds <= 0 {
		timeoutSeconds = 8
	}
	return &Client{
		baseURL:  base,
		apiToken: token,
		httpClient: &http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
		},
	}
}

// doRequest 发起请求并把 response body 反序列化到 out(nil 则忽略)。
//
// 行为:
//   - 网络/解析错误:返回 wrapped error
//   - HTTP 4xx/5xx:尝试解出 {"error": "..."},否则用原始 body
//   - 2xx 但 body 含 {"error": ...}:也视为错误
func (c *Client) doRequest(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body: %w", err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("User-Agent", "Arcway-Telegram-Bot/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errEnv struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		if jerr := json.Unmarshal(bodyBytes, &errEnv); jerr == nil {
			if errEnv.Error != "" {
				return fmt.Errorf("HTTP %d: %s", resp.StatusCode, errEnv.Error)
			}
			if errEnv.Message != "" {
				return fmt.Errorf("HTTP %d: %s", resp.StatusCode, errEnv.Message)
			}
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(bodyBytes), 256))
	}

	if out != nil {
		if err := json.Unmarshal(bodyBytes, out); err != nil {
			return fmt.Errorf("unmarshal response: %w (body: %s)", err, truncate(string(bodyBytes), 256))
		}
	}
	return nil
}

func (c *Client) get(ctx context.Context, path string, q url.Values, out any) error {
	if len(q) > 0 {
		path = path + "?" + q.Encode()
	}
	return c.doRequest(ctx, http.MethodGet, path, nil, out)
}

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	return c.doRequest(ctx, http.MethodPost, path, body, out)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
