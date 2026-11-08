package xui

import (
	"fmt"
)

var supportedProtocols = map[string]bool{
	"vless":         true,
	"vmess":         true,
	"trojan":        true,
	"shadowsocks":   true,
	"hysteria2":     true,
	"wireguard":     true,
	"socks":         true,
	"http":          true,
	"dokodemo-door": true,
}

// Inspect evaluates 3x-ui inbounds against existing RelayDock inventory without making mutations.
func Inspect(model *XUIModel, servers []*ServerInfo, existingNodes []*ExistingNodeInfo) *XUIInspectReport {
	report := &XUIInspectReport{
		Protocols: make(map[string]int),
		Warnings:  make([]string, 0),
	}

	if model == nil {
		report.Warnings = append(report.Warnings, "No model data provided")
		return report
	}

	report.TotalInbounds = len(model.Inbounds)

	// Build map of existing ports per server host
	existingPortsByHost := make(map[string]map[int]string)
	for _, n := range existingNodes {
		if n == nil {
			continue
		}
		host := n.Host
		port := n.Port
		if host != "" && port > 0 {
			if existingPortsByHost[host] == nil {
				existingPortsByHost[host] = make(map[int]string)
			}
			existingPortsByHost[host][port] = fmt.Sprintf("Node: %s (%s)", n.NodeName, n.Protocol)
		}
	}

	// Map IP -> ServerInfo
	serverByIP := make(map[string]*ServerInfo)
	for _, s := range servers {
		if s != nil && s.IPAddress != "" {
			serverByIP[s.IPAddress] = s
		}
	}

	// Calculate traffic totals
	for _, ct := range model.ClientTraffics {
		report.TotalTrafficUp += ct.Up
		report.TotalTrafficDown += ct.Down
	}

	uniqueClients := make(map[string]bool)

	for _, ib := range model.Inbounds {
		report.Protocols[ib.Protocol]++

		detail := XUIInboundDetail{
			ID:           ib.ID,
			Port:         ib.Port,
			Protocol:     ib.Protocol,
			Remark:       ib.Remark,
			Tag:          ib.Tag,
			ClientsCount: len(ib.Clients),
			Compatible:   supportedProtocols[ib.Protocol],
		}

		if !detail.Compatible {
			detail.Warning = fmt.Sprintf("Protocol '%s' is not natively supported", ib.Protocol)
			report.Warnings = append(report.Warnings, fmt.Sprintf("Inbound port %d uses unsupported protocol: %s", ib.Port, ib.Protocol))
		}

		// Stream details
		if ib.Stream != nil {
			detail.Network = ib.Stream.Network
			detail.Security = ib.Stream.Security
			if ib.Stream.Security == "reality" && ib.Stream.RealitySettings != nil {
				rs := ib.Stream.RealitySettings
				if len(rs.ServerNames) > 0 {
					detail.SNI = rs.ServerNames[0]
				} else if rs.ServerName != "" {
					detail.SNI = rs.ServerName
				}
				if rs.PrivateKey == "" && rs.PublicKey == "" {
					detail.Warning = "Reality configuration missing both privateKey and publicKey"
					report.Warnings = append(report.Warnings, fmt.Sprintf("Inbound port %d Reality lacks keys", ib.Port))
				}
			} else if ib.Stream.TLSSettings != nil {
				detail.SNI = ib.Stream.TLSSettings.ServerName
			}
		}

		// Client details
		for _, cli := range ib.Clients {
			if cli.Email != "" {
				detail.ClientEmails = append(detail.ClientEmails, cli.Email)
				uniqueClients[cli.Email] = true
			}
		}

		// Server matching
		if ib.Listen != "" && ib.Listen != "0.0.0.0" && ib.Listen != "::" {
			if s, ok := serverByIP[ib.Listen]; ok {
				detail.MatchingServerID = s.ID
				detail.MatchingServerName = s.Name
			}
		}
		if detail.MatchingServerID == 0 && len(servers) == 1 {
			// Single server convenience match
			detail.MatchingServerID = servers[0].ID
			detail.MatchingServerName = servers[0].Name
		}

		// Conflict check
		matchedHost := ""
		if detail.MatchingServerID > 0 {
			for _, s := range servers {
				if s.ID == detail.MatchingServerID {
					matchedHost = s.IPAddress
					break
				}
			}
		}
		if matchedHost != "" {
			if existing, ok := existingPortsByHost[matchedHost][ib.Port]; ok {
				detail.PortConflict = true
				detail.ExistingConflict = existing
				report.HasConflicts = true
				report.Warnings = append(report.Warnings, fmt.Sprintf("Port %d conflicts on server %s (%s)", ib.Port, detail.MatchingServerName, existing))
			}
		}

		report.InboundDetails = append(report.InboundDetails, detail)
	}

	report.TotalClients = len(uniqueClients)
	if report.TotalClients == 0 && len(model.ClientTraffics) > 0 {
		report.TotalClients = len(model.ClientTraffics)
	}

	return report
}
