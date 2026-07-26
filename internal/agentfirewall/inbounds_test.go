package agentfirewall

import (
	"reflect"
	"strings"
	"testing"
)

func TestRulesFromReaderDerivesPublicInboundSockets(t *testing.T) {
	config := `{
  "inbounds": [
    {"tag":"api","listen":"127.0.0.1","port":10085,"protocol":"dokodemo-door","settings":{"network":"tcp"}},
    {"tag":"local-metrics","listen":"::1","port":9090,"protocol":"dokodemo-door","settings":{"network":"tcp,udp"}},
    {"tag":"tunnel","port":2033,"protocol":"tunnel","settings":{"network":"tcp,udp"}},
    {"tag":"wg","port":51820,"protocol":"wireguard"},
    {"tag":"vmess-ws","port":443,"protocol":"vmess","streamSettings":{"network":"ws"}},
    {"tag":"vless-kcp","port":"8443","protocol":"vless","streamSettings":{"network":"kcp"}},
    {"tag":"hy2","port":8444,"protocol":"hysteria","streamSettings":{"network":"hysteria"}},
    {"tag":"ss","port":8388,"protocol":"shadowsocks","settings":{"network":"tcp,udp"}},
    {"tag":"socks","port":1080,"protocol":"socks","settings":{"udp":true}},
    {"tag":"mixed","port":2080,"protocol":"mixed","settings":{"udp":true}},
    {"tag":"duplicate","port":443,"protocol":"trojan","streamSettings":{"network":"tcp"}}
  ]
}`
	rules, err := RulesFromReader(strings.NewReader(config))
	if err != nil {
		t.Fatal(err)
	}
	want := []PortRule{
		{Protocol: "tcp", Port: 443},
		{Protocol: "tcp", Port: 1080},
		{Protocol: "tcp", Port: 2033},
		{Protocol: "tcp", Port: 2080},
		{Protocol: "tcp", Port: 8388},
		{Protocol: "udp", Port: 1080},
		{Protocol: "udp", Port: 2033},
		{Protocol: "udp", Port: 2080},
		{Protocol: "udp", Port: 8388},
		{Protocol: "udp", Port: 8443},
		{Protocol: "udp", Port: 8444},
		{Protocol: "udp", Port: 51820},
	}
	if !reflect.DeepEqual(rules, want) {
		t.Fatalf("rules=%#v want=%#v", rules, want)
	}
}

func TestRulesFromReaderRejectsUnsupportedPortShapes(t *testing.T) {
	for _, port := range []string{`"2033-2035"`, `0`, `65536`, `1.5`} {
		config := `{"inbounds":[{"tag":"public","protocol":"vless","port":` + port + `}]}`
		if _, err := RulesFromReader(strings.NewReader(config)); err == nil {
			t.Fatalf("port %s was accepted", port)
		}
	}
}

func TestRulesFromReaderAllowsConfigWithoutInbounds(t *testing.T) {
	rules, err := RulesFromReader(strings.NewReader(`{"outbounds":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("rules=%#v want empty", rules)
	}
}
