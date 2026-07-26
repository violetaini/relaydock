package dnscredentials

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const (
	CloudflareEmailKey  = "CF_API_EMAIL"
	CloudflareGlobalKey = "CF_API_KEY"
	CloudflareTokenKey  = "CF_DNS_API_TOKEN"
)

type CloudflareAuthMode string

const (
	CloudflareAuthToken  CloudflareAuthMode = "token"
	CloudflareAuthGlobal CloudflareAuthMode = "global"
)

// CloudflareAuth is the unambiguous authentication form used by all DNS paths.
type CloudflareAuth struct {
	Mode   CloudflareAuthMode
	Email  string
	Secret string
}

// ResolveCloudflare accepts both legacy stored forms. A complete email/global-key
// pair wins over a token when an old record contains both, so a Global API Key is
// never accidentally sent as a Bearer token.
func ResolveCloudflare(credentials map[string]string) (CloudflareAuth, error) {
	email := strings.TrimSpace(credentials[CloudflareEmailKey])
	globalKey := strings.TrimSpace(credentials[CloudflareGlobalKey])
	token := strings.TrimSpace(credentials[CloudflareTokenKey])

	if email != "" && globalKey != "" {
		return CloudflareAuth{Mode: CloudflareAuthGlobal, Email: email, Secret: globalKey}, nil
	}
	if token != "" {
		return CloudflareAuth{Mode: CloudflareAuthToken, Secret: token}, nil
	}
	if email != "" {
		return CloudflareAuth{}, errors.New("Cloudflare Global API Key 模式缺少 API 密钥")
	}
	if globalKey != "" {
		return CloudflareAuth{}, errors.New("Cloudflare Global API Key 模式缺少账户邮箱；如果填写的是 API Token，请留空邮箱并重新保存")
	}
	return CloudflareAuth{}, errors.New("Cloudflare 凭据不能为空")
}

// NormalizeCloudflare returns only the keys required for the selected mode.
func NormalizeCloudflare(credentials map[string]string) (map[string]string, error) {
	auth, err := ResolveCloudflare(credentials)
	if err != nil {
		return nil, err
	}
	if auth.Mode == CloudflareAuthGlobal {
		return map[string]string{
			CloudflareEmailKey:  auth.Email,
			CloudflareGlobalKey: auth.Secret,
		}, nil
	}
	return map[string]string{CloudflareTokenKey: auth.Secret}, nil
}

func (a CloudflareAuth) Apply(req *http.Request) {
	if a.Mode == CloudflareAuthGlobal {
		req.Header.Set("X-Auth-Email", a.Email)
		req.Header.Set("X-Auth-Key", a.Secret)
		return
	}
	req.Header.Set("Authorization", "Bearer "+a.Secret)
}

// FriendlyCloudflareError keeps the original error for logs while making the
// common authentication-header failure actionable in the UI.
func FriendlyCloudflareError(err error) error {
	if err == nil {
		return nil
	}
	message := strings.ToLower(err.Error())
	code := ""
	switch {
	case strings.Contains(message, "6003"):
		code = "6003"
	case strings.Contains(message, "6103"):
		code = "6103"
	case strings.Contains(message, "invalid request headers"),
		strings.Contains(message, "invalid format for authorization header"):
		code = "6003/6103"
	default:
		return err
	}
	return fmt.Errorf("Cloudflare 鉴权失败（错误 %s）：请检查凭据类型。使用 API Token 时请留空账户邮箱；使用 Global API Key 时请填写 Cloudflare 登录邮箱，并在“API 密钥”中填写 Global API Key。原始错误：%w", code, err)
}
