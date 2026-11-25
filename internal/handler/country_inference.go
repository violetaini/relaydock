package handler

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// extractCountryCodeFromEmoji 从包含 Unicode 国旗 Emoji 的字符串中提取 ISO 3166-1 两位国家代码。
// 国旗 Emoji 是由两个连续的 Unicode 区域指示符符號 (Regional Indicator Symbols U+1F1E6 ~ U+1F1FF) 组成的。
func extractCountryCodeFromEmoji(s string) string {
	runes := []rune(s)
	for i := 0; i+1 < len(runes); i++ {
		r1, r2 := runes[i], runes[i+1]
		if r1 >= 0x1F1E6 && r1 <= 0x1F1FF && r2 >= 0x1F1E6 && r2 <= 0x1F1FF {
			c1 := byte('A' + (r1 - 0x1F1E6))
			c2 := byte('A' + (r2 - 0x1F1E6))
			code := string([]byte{c1, c2})
			if valid := publicCountryCode(code); valid != "" {
				return valid
			}
		}
	}
	return ""
}

// 机场常用三字代码与国家/地区映射
var iataCountryCodeMap = map[string]string{
	"HKG": "HK",
	"NRT": "JP", "HND": "JP", "KIX": "JP", "FUK": "JP", "CTS": "JP", "NGO": "JP",
	"TPE": "TW", "TSA": "TW", "KHH": "TW",
	"SIN": "SG",
	"ICN": "KR", "GMP": "KR", "PUS": "KR",
	"LAX": "US", "SJC": "US", "SFO": "US", "SEA": "US", "ORD": "US", "DFW": "US",
	"JFK": "US", "EWR": "US", "IAD": "US", "MIA": "US", "ATL": "US", "PHX": "US",
	"LHR": "GB", "LGW": "GB", "MAN": "GB",
	"FRA": "DE", "MUC": "DE", "BER": "DE",
	"CDG": "FR", "ORY": "FR",
	"AMS": "NL",
	"SYD": "AU", "MEL": "AU", "BNE": "AU", "PER": "AU",
	"YYZ": "CA", "YVR": "CA", "YUL": "CA",
	"ZRH": "CH", "GVA": "CH",
	"DXB": "AE", "AUH": "AE",
	"BKK": "TH", "DMK": "TH",
	"KUL": "MY",
	"SGN": "VN", "HAN": "VN",
	"MNL": "PH",
	"CGK": "ID",
	"DEL": "IN", "BOM": "IN", "BLR": "IN",
	"IST": "TR",
	"SVO": "RU", "DME": "RU",
	"GRU": "BR", "GIG": "BR",
	"EZE": "AR",
	"MEX": "MX",
	"JNB": "ZA", "CPT": "ZA",
}

// 标签与前缀正则表达式，避免普通英文单词（如 SHAKE, APPLE, TASK）误匹配
var prefixCodePattern = regexp.MustCompile(`(?i)(?:^|[\s\[\(\-\_\|])([A-Z]{2})(?:[\s\]\)\-\_\|\d]|$)`)

// inferCountryCodeFromName 从节点名称智能推导国家代码（0ms 零延迟本地解析）。
// 包含 Emoji 原生解码、全球机场 IATA 航字三字码、前后缀标记提取与简繁双语地名匹配。
func inferCountryCodeFromName(name string) string {
	if trimmed := strings.TrimSpace(name); trimmed == "" {
		return "UN"
	}

	// 1. Emoji 国旗优先匹配（100% 准确）
	if code := extractCountryCodeFromEmoji(name); code != "" {
		return code
	}

	nameUpper := strings.ToUpper(name)

	// 2. IATA 机场代码精准匹配
	for iata, code := range iataCountryCodeMap {
		if strings.Contains(nameUpper, iata) {
			return code
		}
	}

	// 3. 常见独立标记/前缀（如 [HK], HK-, SG_）
	matches := prefixCodePattern.FindAllStringSubmatch(name, -1)
	for _, m := range matches {
		if len(m) >= 2 {
			candidate := strings.ToUpper(m[1])
			switch candidate {
			case "HK", "TW", "JP", "US", "SG", "KR", "UK", "GB", "DE", "FR", "NL", "CA", "AU", "RU", "TR", "IN", "MO", "TH", "MY", "VN", "PH", "ID", "CH", "SE", "NO", "FI", "IE", "IT", "ES", "PT", "BR", "AR", "AE", "ZA", "MX":
				if candidate == "UK" {
					return "GB"
				}
				return candidate
			}
		}
	}

	// 4. 简繁体地名与城市匹配
	switch {
	case strings.Contains(name, "香港") || strings.Contains(nameUpper, "HONG KONG"):
		return "HK"
	case strings.Contains(name, "日本") || strings.Contains(name, "东京") || strings.Contains(name, "大阪") || strings.Contains(name, "名古屋") || strings.Contains(name, "福冈") || strings.Contains(name, "札幌") || strings.Contains(nameUpper, "TOKYO") || strings.Contains(nameUpper, "OSAKA") || strings.Contains(nameUpper, "JAPAN"):
		return "JP"
	case strings.Contains(name, "台湾") || strings.Contains(name, "臺灣") || strings.Contains(name, "台北") || strings.Contains(name, "臺北") || strings.Contains(name, "高雄") || strings.Contains(name, "台中") || strings.Contains(nameUpper, "TAIWAN") || strings.Contains(nameUpper, "TAIPEI"):
		return "TW"
	case strings.Contains(name, "美国") || strings.Contains(name, "洛杉矶") || strings.Contains(name, "圣何塞") || strings.Contains(name, "旧金山") || strings.Contains(name, "硅谷") || strings.Contains(name, "西雅图") || strings.Contains(name, "芝加哥") || strings.Contains(name, "纽约") || strings.Contains(name, "波特兰") || strings.Contains(name, "达拉斯") || strings.Contains(name, "迈阿密") || strings.Contains(name, "亚特兰大") || strings.Contains(nameUpper, "UNITED STATES") || strings.Contains(nameUpper, "LOS ANGELES") || strings.Contains(nameUpper, "SAN JOSE") || strings.Contains(nameUpper, "SILICON VALLEY") || strings.Contains(nameUpper, "NEW YORK"):
		return "US"
	case strings.Contains(name, "新加坡") || strings.Contains(name, "星加坡") || strings.Contains(name, "狮城") || strings.Contains(nameUpper, "SINGAPORE"):
		return "SG"
	case strings.Contains(name, "韩国") || strings.Contains(name, "首尔") || strings.Contains(name, "南韩") || strings.Contains(name, "釜山") || strings.Contains(nameUpper, "KOREA") || strings.Contains(nameUpper, "SEOUL"):
		return "KR"
	case strings.Contains(name, "英国") || strings.Contains(name, "伦敦") || strings.Contains(name, "大不列颠") || strings.Contains(name, "曼彻斯特") || strings.Contains(nameUpper, "UNITED KINGDOM") || strings.Contains(nameUpper, "LONDON"):
		return "GB"
	case strings.Contains(name, "德国") || strings.Contains(name, "法兰克福") || strings.Contains(name, "柏林") || strings.Contains(name, "慕尼黑") || strings.Contains(nameUpper, "GERMANY") || strings.Contains(nameUpper, "FRANKFURT"):
		return "DE"
	case strings.Contains(name, "法国") || strings.Contains(name, "巴黎") || strings.Contains(nameUpper, "FRANCE") || strings.Contains(nameUpper, "PARIS"):
		return "FR"
	case strings.Contains(name, "荷兰") || strings.Contains(name, "阿姆斯特丹") || strings.Contains(nameUpper, "NETHERLANDS") || strings.Contains(nameUpper, "AMSTERDAM"):
		return "NL"
	case strings.Contains(name, "加拿大") || strings.Contains(name, "多伦多") || strings.Contains(name, "温哥华") || strings.Contains(name, "蒙特利尔") || strings.Contains(nameUpper, "CANADA") || strings.Contains(nameUpper, "TORONTO") || strings.Contains(nameUpper, "VANCOUVER"):
		return "CA"
	case strings.Contains(name, "澳大利亚") || strings.Contains(name, "澳洲") || strings.Contains(name, "悉尼") || strings.Contains(name, "墨尔本") || strings.Contains(name, "珀斯") || strings.Contains(nameUpper, "AUSTRALIA") || strings.Contains(nameUpper, "SYDNEY") || strings.Contains(nameUpper, "MELBOURNE"):
		return "AU"
	case strings.Contains(name, "俄罗斯") || strings.Contains(name, "莫斯科") || strings.Contains(name, "圣彼得堡") || strings.Contains(nameUpper, "RUSSIA") || strings.Contains(nameUpper, "MOSCOW"):
		return "RU"
	case strings.Contains(name, "土耳其") || strings.Contains(name, "伊斯坦布尔") || strings.Contains(nameUpper, "TURKEY") || strings.Contains(nameUpper, "ISTANBUL"):
		return "TR"
	case strings.Contains(name, "印度") || strings.Contains(name, "新德里") || strings.Contains(name, "孟买") || strings.Contains(nameUpper, "INDIA") || strings.Contains(nameUpper, "MUMBAI"):
		return "IN"
	case strings.Contains(name, "澳门") || strings.Contains(name, "澳門") || strings.Contains(nameUpper, "MACAU") || strings.Contains(nameUpper, "MACAO"):
		return "MO"
	case strings.Contains(name, "泰国") || strings.Contains(name, "曼谷") || strings.Contains(nameUpper, "THAILAND") || strings.Contains(nameUpper, "BANGKOK"):
		return "TH"
	case strings.Contains(name, "越南") || strings.Contains(name, "胡志明") || strings.Contains(name, "河内") || strings.Contains(nameUpper, "VIETNAM") || strings.Contains(nameUpper, "HANOI"):
		return "VN"
	case strings.Contains(name, "菲律宾") || strings.Contains(name, "马尼拉") || strings.Contains(nameUpper, "PHILIPPINES") || strings.Contains(nameUpper, "MANILA"):
		return "PH"
	case strings.Contains(name, "马来西亚") || strings.Contains(name, "吉隆坡") || strings.Contains(name, "大马") || strings.Contains(nameUpper, "MALAYSIA") || strings.Contains(nameUpper, "KUALA LUMPUR"):
		return "MY"
	case strings.Contains(name, "印度尼西亚") || strings.Contains(name, "印尼") || strings.Contains(name, "雅加达") || strings.Contains(nameUpper, "INDONESIA") || strings.Contains(nameUpper, "JAKARTA"):
		return "ID"
	case strings.Contains(name, "瑞士") || strings.Contains(name, "苏黎世") || strings.Contains(name, "日内瓦") || strings.Contains(nameUpper, "SWITZERLAND") || strings.Contains(nameUpper, "ZURICH"):
		return "CH"
	case strings.Contains(name, "瑞典") || strings.Contains(name, "斯德哥尔摩") || strings.Contains(nameUpper, "SWEDEN"):
		return "SE"
	case strings.Contains(name, "挪威") || strings.Contains(name, "奥斯陆") || strings.Contains(nameUpper, "NORWAY"):
		return "NO"
	case strings.Contains(name, "芬兰") || strings.Contains(name, "赫尔辛基") || strings.Contains(nameUpper, "FINLAND"):
		return "FI"
	case strings.Contains(name, "爱尔兰") || strings.Contains(name, "都柏林") || strings.Contains(nameUpper, "IRELAND"):
		return "IE"
	case strings.Contains(name, "意大利") || strings.Contains(name, "罗马") || strings.Contains(name, "米兰") || strings.Contains(nameUpper, "ITALY"):
		return "IT"
	case strings.Contains(name, "西班牙") || strings.Contains(name, "马德里") || strings.Contains(name, "巴塞罗那") || strings.Contains(nameUpper, "SPAIN"):
		return "ES"
	case strings.Contains(name, "葡萄牙") || strings.Contains(name, "里斯本") || strings.Contains(nameUpper, "PORTUGAL"):
		return "PT"
	case strings.Contains(name, "阿联酋") || strings.Contains(name, "迪拜") || strings.Contains(name, "阿布扎比") || strings.Contains(nameUpper, "DUBAI"):
		return "AE"
	case strings.Contains(name, "巴西") || strings.Contains(name, "圣保罗") || strings.Contains(nameUpper, "BRAZIL"):
		return "BR"
	case strings.Contains(name, "阿根廷") || strings.Contains(nameUpper, "ARGENTINA"):
		return "AR"
	case strings.Contains(name, "南非") || strings.Contains(nameUpper, "SOUTH AFRICA"):
		return "ZA"
	case strings.Contains(name, "墨西哥") || strings.Contains(nameUpper, "MEXICO"):
		return "MX"
	default:
		return "UN"
	}
}

// probeProxyLandingCountry 尝试通过代理节点实际发起轻量请求，获取真实落地 IP 并解析其所属国家。
// 当且仅当节点的名称无法识别地区，必须落到 IP/域名判断时触发（落地 IP 优先于入口中转 IP）。
func probeProxyLandingCountry(p map[string]any) string {
	proto := strings.ToLower(strings.TrimSpace(fmt.Sprint(p["type"])))
	server := strings.TrimSpace(fmt.Sprint(p["server"]))
	if server == "" || server == "<nil>" {
		return ""
	}
	port := 0
	switch v := p["port"].(type) {
	case int:
		port = v
	case float64:
		port = int(v)
	case string:
		port, _ = strconv.Atoi(v)
	}
	if port <= 0 {
		return ""
	}

	// 构造快速探测 Client (1.5s 超时，防止阻塞任何页面响应)
	timeout := 1500 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var transport *http.Transport

	switch proto {
	case "socks5", "socks":
		auth := &proxy.Auth{}
		if u := fmt.Sprint(p["username"]); u != "" && u != "<nil>" {
			auth.User = u
			auth.Password = fmt.Sprint(p["password"])
		} else {
			auth = nil
		}
		dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort(server, strconv.Itoa(port)), auth, &net.Dialer{Timeout: timeout})
		if err != nil {
			return ""
		}
		transport = &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			},
			DisableKeepAlives: true,
		}
	case "http":
		proxyURL, err := url.Parse(fmt.Sprintf("http://%s:%d", server, port))
		if err != nil {
			return ""
		}
		if u := fmt.Sprint(p["username"]); u != "" && u != "<nil>" {
			proxyURL.User = url.UserPassword(u, fmt.Sprint(p["password"]))
		}
		transport = &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			DisableKeepAlives: true,
		}
	default:
		// 对于 vmess, vless, trojan 等需完整客户端协议的节点，若无法快速建立标准 dialer，
		// 返回空，优雅回退到入口 server GeoIP
		return ""
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://api.ipify.org", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "curl/7.88.1")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			landingIP := strings.TrimSpace(string(body))
			if net.ParseIP(landingIP) != nil {
				return getGeoIPCountryCode(landingIP)
			}
		}
	}
	return ""
}

// resolveProxyCountryCodeWithLandingProbe 多层渐进式地区解析引擎：
// 1. 显式覆盖（_rd_country_code 或用户自定义）；
// 2. 内部服务器映射 (hostCountryMap)；
// 3. 节点名称智能解析（Unicode Emoji 国旗原生解码 + IATA 三字码 + 简繁双语词库）；
// 4. 必须通过 IP 确定时：优先实际测出落地 IP 确定归属地，探测失败或不支持时回退入口 Server GeoIP 探测；
// 5. 最终未知兜底 "UN"。
func resolveProxyCountryCodeWithLandingProbe(p map[string]any, hostCountryMap map[string]string) string {
	// 1. 显式绑定的地区（如外部订阅导入时用户改选的地区，或 _rd_country_code）
	if explicit, ok := p["_rd_country_code"].(string); ok {
		if code := publicCountryCode(explicit); code != "" {
			return code
		}
	}

	// 2. 内部纳管服务器映射
	if len(hostCountryMap) > 0 {
		host := strings.ToLower(strings.TrimSpace(fmt.Sprint(p["server"])))
		if host != "" && host != "<nil>" {
			if cc := hostCountryMap[host]; cc != "" {
				return cc
			}
		}
	}

	// 3. 智能名称与国旗解析 (0ms 零延迟)
	name := fmt.Sprint(p["name"])
	if code := inferCountryCodeFromName(name); code != "" && code != "UN" {
		return code
	}

	// 4. 必须通过 IP 确定：优先通过实际链接获取落地 IP 确定归属地
	if landingCC := probeProxyLandingCountry(p); landingCC != "" {
		return landingCC
	}

	// 4.1 落地 IP 探测不通或不支持协议时，回退到节点配置的 Server 地址 (IP 或域名解析后 GeoIP)
	server := strings.TrimSpace(fmt.Sprint(p["server"]))
	if server != "" && server != "<nil>" {
		if geoCC := getGeoIPCountryCode(server); geoCC != "" {
			return geoCC
		}
	}

	return "UN"
}
