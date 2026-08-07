package bot

import (
	_ "embed"
	"net/http"
)

// Mini App 顶部 logo 使用 Arcway 自己的默认品牌资源并内嵌到二进制。
// 不依赖外部 URL;路由放在 /api/tg-webapp/ 下,确保被现有 nginx 反代覆盖。
//
//go:embed assets/brand.png
var brandLogo []byte

func (s *Service) webAppLogoLight(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(brandLogo)
}

func (s *Service) webAppLogoDark(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(brandLogo)
}
