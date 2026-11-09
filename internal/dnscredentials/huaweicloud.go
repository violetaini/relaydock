package dnscredentials

import (
	"errors"
	"fmt"
	"strings"
)

const (
	HuaweiCloudAccessKeyIDKey     = "HUAWEICLOUD_ACCESS_KEY_ID"
	HuaweiCloudSecretAccessKeyKey = "HUAWEICLOUD_SECRET_ACCESS_KEY"
	HuaweiCloudRegionKey          = "HUAWEICLOUD_REGION"
	DefaultHuaweiCloudRegion      = "cn-north-4"
)

// NormalizeHuaweiCloud 规范化华为云 DNS 凭据。
// 兼容 HUAWEICLOUD_ACCESS_KEY_ID、AccessKeyId、ak 等多种命名风格；
// 若未指定 Region，则自动默认使用公共 DNS 所在的 cn-north-4（北京四）。
func NormalizeHuaweiCloud(credentials map[string]string) (map[string]string, error) {
	if len(credentials) == 0 {
		return nil, errors.New("华为云 DNS 凭据不能为空")
	}

	ak := ""
	sk := ""
	region := ""

	for k, v := range credentials {
		val := strings.TrimSpace(v)
		if val == "" {
			continue
		}
		lower := strings.ToLower(strings.TrimSpace(k))
		switch lower {
		case "huaweicloud_access_key_id", "accesskeyid", "access_key_id", "accesskey", "ak":
			ak = val
		case "huaweicloud_secret_access_key", "secretaccesskey", "secret_access_key", "secretkey", "sk":
			sk = val
		case "huaweicloud_region", "region":
			region = val
		}
	}

	if ak == "" {
		return nil, errors.New("华为云 DNS 凭据缺少 AccessKey ID (AK)")
	}
	if sk == "" {
		return nil, errors.New("华为云 DNS 凭据缺少 Secret Access Key (SK)")
	}
	if region == "" {
		region = DefaultHuaweiCloudRegion
	}

	return map[string]string{
		HuaweiCloudAccessKeyIDKey:     ak,
		HuaweiCloudSecretAccessKeyKey: sk,
		HuaweiCloudRegionKey:          region,
	}, nil
}

// FriendlyHuaweiCloudError 将华为云常见的鉴权或配额错误转换为更易操作的提示信息。
func FriendlyHuaweiCloudError(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "auth") || strings.Contains(msg, "signature") || strings.Contains(msg, "credentials") || strings.Contains(msg, "accesskey"):
		return fmt.Errorf("华为云鉴权失败：请检查 AccessKey ID (AK) 与 Secret Access Key (SK) 是否有效且具有 DNS 管理权限（DNS FullAccess）。原始错误：%w", err)
	case strings.Contains(msg, "zone") && strings.Contains(msg, "not found"):
		return fmt.Errorf("华为云 DNS 未找到对应公网域名解析区（Zone），请确认域名已在华为云云解析服务中创建。原始错误：%w", err)
	default:
		return err
	}
}
