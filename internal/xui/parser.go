package xui

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

const (
	maxExtractBytes = 500 << 20 // 500 MB
	maxArchiveFiles = 2_000
)

// ParseXUIJSON parses 3x-ui inbounds from raw JSON.
func ParseXUIJSON(data []byte) (*XUIModel, error) {
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) == 0 {
		return nil, errors.New("empty JSON data")
	}

	model := &XUIModel{
		Source:   "json",
		Settings: make(map[string]string),
	}

	// 1. Try wrapped format: { "success": true, "obj": [ ... ] } or { "data": [ ... ] }
	var wrapper struct {
		Success  *bool             `json:"success"`
		Obj      []json.RawMessage `json:"obj"`
		Data     []json.RawMessage `json:"data"`
		Inbounds []json.RawMessage `json:"inbounds"`
	}
	if err := json.Unmarshal(data, &wrapper); err == nil && (len(wrapper.Obj) > 0 || len(wrapper.Data) > 0 || len(wrapper.Inbounds) > 0) {
		candidates := wrapper.Obj
		if len(candidates) == 0 {
			candidates = wrapper.Data
		}
		if len(candidates) == 0 {
			candidates = wrapper.Inbounds
		}
		for _, raw := range candidates {
			ib, err := parseSingleInboundJSON(raw)
			if err != nil {
				continue
			}
			model.Inbounds = append(model.Inbounds, *ib)
		}
		extractClientTrafficsFromInbounds(model)
		return model, nil
	}

	// 2. Try raw array format: [ { ... }, { ... } ]
	var rawList []json.RawMessage
	if err := json.Unmarshal(data, &rawList); err == nil && len(rawList) > 0 {
		for _, raw := range rawList {
			ib, err := parseSingleInboundJSON(raw)
			if err != nil {
				continue
			}
			model.Inbounds = append(model.Inbounds, *ib)
		}
		extractClientTrafficsFromInbounds(model)
		return model, nil
	}

	// 3. Try single object format: { ... }
	ib, err := parseSingleInboundJSON(data)
	if err == nil && ib.Port > 0 && ib.Protocol != "" {
		model.Inbounds = append(model.Inbounds, *ib)
		extractClientTrafficsFromInbounds(model)
		return model, nil
	}

	return nil, fmt.Errorf("unable to recognize 3x-ui inbounds JSON schema: %w", err)
}

func parseSingleInboundJSON(raw []byte) (*XUIInbound, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}

	ib := &XUIInbound{}
	if v, ok := m["id"].(float64); ok {
		ib.ID = int64(v)
	}
	if v, ok := m["user_id"].(float64); ok {
		ib.UserID = int64(v)
	}
	if v, ok := m["up"].(float64); ok {
		ib.Up = int64(v)
	}
	if v, ok := m["down"].(float64); ok {
		ib.Down = int64(v)
	}
	if v, ok := m["total"].(float64); ok {
		ib.Total = int64(v)
	}
	if v, ok := m["remark"].(string); ok {
		ib.Remark = strings.TrimSpace(v)
	}
	if v, ok := m["enable"].(bool); ok {
		ib.Enable = v
	} else if v, ok := m["enable"].(float64); ok {
		ib.Enable = v > 0
	}
	if v, ok := m["expiry_time"].(float64); ok {
		ib.ExpiryTime = int64(v)
	} else if v, ok := m["expiryTime"].(float64); ok {
		ib.ExpiryTime = int64(v)
	}
	if v, ok := m["listen"].(string); ok {
		ib.Listen = strings.TrimSpace(v)
	}
	if v, ok := m["port"].(float64); ok {
		ib.Port = int(v)
	}
	if v, ok := m["protocol"].(string); ok {
		ib.Protocol = strings.ToLower(strings.TrimSpace(v))
	}
	if v, ok := m["tag"].(string); ok {
		ib.Tag = strings.TrimSpace(v)
	}
	if ib.Tag == "" && ib.Port > 0 {
		ib.Tag = fmt.Sprintf("inbound-%d", ib.Port)
	}

	// Settings parsing
	if rawSettings, ok := m["settings"].(string); ok {
		ib.RawSettings = rawSettings
		parseInboundSettings(ib, []byte(rawSettings))
	} else if objSettings, ok := m["settings"].(map[string]interface{}); ok {
		b, _ := json.Marshal(objSettings)
		ib.RawSettings = string(b)
		parseInboundSettings(ib, b)
	}

	// Stream settings parsing
	var streamRaw []byte
	if rawStream, ok := m["stream_settings"].(string); ok {
		streamRaw = []byte(rawStream)
	} else if rawStream, ok := m["streamSettings"].(string); ok {
		streamRaw = []byte(rawStream)
	} else if objStream, ok := m["stream_settings"].(map[string]interface{}); ok {
		streamRaw, _ = json.Marshal(objStream)
	} else if objStream, ok := m["streamSettings"].(map[string]interface{}); ok {
		streamRaw, _ = json.Marshal(objStream)
	}

	if len(streamRaw) > 0 {
		ib.RawStreamSettings = string(streamRaw)
		var stream XUIStreamSettings
		if err := json.Unmarshal(streamRaw, &stream); err == nil {
			ib.Stream = &stream
			// Normalize reality serverName fallback
			if stream.RealitySettings != nil {
				if len(stream.RealitySettings.ServerNames) == 0 && stream.RealitySettings.ServerName != "" {
					stream.RealitySettings.ServerNames = []string{stream.RealitySettings.ServerName}
				}
				if len(stream.RealitySettings.ShortIds) == 0 && stream.RealitySettings.ShortId != "" {
					stream.RealitySettings.ShortIds = []string{stream.RealitySettings.ShortId}
				}
			}
		}
	}

	return ib, nil
}

func parseInboundSettings(ib *XUIInbound, data []byte) {
	if len(data) == 0 {
		return
	}
	var setMap map[string]interface{}
	if err := json.Unmarshal(data, &setMap); err != nil {
		return
	}

	// 1. clients array (VLESS, VMess, Trojan, SS-2022)
	for _, key := range []string{"clients", "users", "accounts"} {
		if rawClients, ok := setMap[key].([]interface{}); ok && len(rawClients) > 0 {
			for _, item := range rawClients {
				cMap, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				cli := XUIClient{Enable: true}
				if id, ok := cMap["id"].(string); ok {
					cli.ID = strings.TrimSpace(id)
				}
				if pwd, ok := cMap["password"].(string); ok {
					cli.Password = strings.TrimSpace(pwd)
				}
				if cli.ID == "" && cli.Password != "" {
					cli.ID = cli.Password
				}
				if email, ok := cMap["email"].(string); ok {
					cli.Email = strings.TrimSpace(email)
				}
				if flow, ok := cMap["flow"].(string); ok {
					cli.Flow = strings.TrimSpace(flow)
				}
				if subId, ok := cMap["subId"].(string); ok {
					cli.SubID = strings.TrimSpace(subId)
				}
				if method, ok := cMap["method"].(string); ok {
					cli.Method = strings.TrimSpace(method)
				}
				if tot, ok := cMap["totalGB"].(float64); ok {
					cli.TotalGB = int64(tot)
				}
				if exp, ok := cMap["expiryTime"].(float64); ok {
					cli.ExpiryTime = int64(exp)
				}
				if en, ok := cMap["enable"].(bool); ok {
					cli.Enable = en
				}
				ib.Clients = append(ib.Clients, cli)
			}
			break
		}
	}

	// 2. Shadowsocks single user password in root settings
	if ib.Protocol == "shadowsocks" && len(ib.Clients) == 0 {
		method, _ := setMap["method"].(string)
		password, _ := setMap["password"].(string)
		if password != "" {
			ib.Clients = append(ib.Clients, XUIClient{
				ID:       password,
				Password: password,
				Method:   method,
				Email:    fmt.Sprintf("ss-%d", ib.Port),
				Enable:   true,
			})
		}
	}
}

func extractClientTrafficsFromInbounds(model *XUIModel) {
	for _, ib := range model.Inbounds {
		for _, cli := range ib.Clients {
			if cli.Email == "" {
				continue
			}
			model.ClientTraffics = append(model.ClientTraffics, XUIClientTraffic{
				InboundID:  ib.ID,
				Email:      cli.Email,
				Enable:     cli.Enable,
				ExpiryTime: cli.ExpiryTime,
				Total:      cli.TotalGB,
			})
		}
	}
}

// ParseXUIDatabase opens and parses SQLite x-ui.db.
func ParseXUIDatabase(dbPath string) (*XUIModel, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("stat x-ui.db: %w", err)
	}

	// Use pure-Go SQLite driver
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite x-ui.db: %w", err)
	}
	defer db.Close()

	model := &XUIModel{
		Source:   "sqlite",
		Settings: make(map[string]string),
	}

	// 1. Read settings table if exists
	rows, err := db.Query("SELECT key, value FROM settings")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var k, v string
			if err := rows.Scan(&k, &v); err == nil {
				model.Settings[k] = v
			}
		}
	}

	// 2. Check inbounds column names to handle variations
	colsRows, err := db.Query("PRAGMA table_info(inbounds)")
	if err != nil {
		return nil, fmt.Errorf("inbounds table not found in x-ui.db: %w", err)
	}
	hasStreamSnake := false
	hasStreamCamel := false
	for colsRows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt *string
		_ = colsRows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk)
		if name == "stream_settings" {
			hasStreamSnake = true
		} else if name == "streamSettings" {
			hasStreamCamel = true
		}
	}
	colsRows.Close()

	streamCol := "stream_settings"
	if hasStreamCamel && !hasStreamSnake {
		streamCol = "streamSettings"
	}

	query := fmt.Sprintf(`SELECT id, user_id, up, down, total, remark, enable, expiry_time, listen, port, protocol, settings, %s, tag FROM inbounds`, streamCol)
	inboundRows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("query inbounds: %w", err)
	}
	defer inboundRows.Close()

	for inboundRows.Next() {
		var ib XUIInbound
		var enableInt int
		var rawStream sql.NullString
		var rawSettings sql.NullString
		var listen sql.NullString
		var tag sql.NullString
		var remark sql.NullString

		if err := inboundRows.Scan(
			&ib.ID, &ib.UserID, &ib.Up, &ib.Down, &ib.Total,
			&remark, &enableInt, &ib.ExpiryTime,
			&listen, &ib.Port, &ib.Protocol,
			&rawSettings, &rawStream, &tag,
		); err != nil {
			continue
		}

		ib.Remark = strings.TrimSpace(remark.String)
		ib.Enable = enableInt > 0
		ib.Listen = strings.TrimSpace(listen.String)
		ib.Tag = strings.TrimSpace(tag.String)
		ib.Protocol = strings.ToLower(strings.TrimSpace(ib.Protocol))
		if ib.Tag == "" && ib.Port > 0 {
			ib.Tag = fmt.Sprintf("inbound-%d", ib.Port)
		}

		if rawSettings.Valid && rawSettings.String != "" {
			ib.RawSettings = rawSettings.String
			parseInboundSettings(&ib, []byte(rawSettings.String))
		}

		if rawStream.Valid && rawStream.String != "" {
			ib.RawStreamSettings = rawStream.String
			var stream XUIStreamSettings
			if err := json.Unmarshal([]byte(rawStream.String), &stream); err == nil {
				ib.Stream = &stream
				if stream.RealitySettings != nil {
					if len(stream.RealitySettings.ServerNames) == 0 && stream.RealitySettings.ServerName != "" {
						stream.RealitySettings.ServerNames = []string{stream.RealitySettings.ServerName}
					}
					if len(stream.RealitySettings.ShortIds) == 0 && stream.RealitySettings.ShortId != "" {
						stream.RealitySettings.ShortIds = []string{stream.RealitySettings.ShortId}
					}
				}
			}
		}

		model.Inbounds = append(model.Inbounds, ib)
	}

	// 3. Read client_traffics table if exists
	ctRows, err := db.Query(`SELECT id, inbound_id, enable, email, up, down, expiry_time, total, reset FROM client_traffics`)
	if err == nil {
		defer ctRows.Close()
		for ctRows.Next() {
			var ct XUIClientTraffic
			var enableInt int
			if err := ctRows.Scan(&ct.ID, &ct.InboundID, &enableInt, &ct.Email, &ct.Up, &ct.Down, &ct.ExpiryTime, &ct.Total, &ct.Reset); err == nil {
				ct.Enable = enableInt > 0
				ct.Email = strings.TrimSpace(ct.Email)
				model.ClientTraffics = append(model.ClientTraffics, ct)
			}
		}
	} else {
		// Fallback: derive client traffics from inbounds
		extractClientTrafficsFromInbounds(model)
	}

	return model, nil
}

// ParseXUIArchive extracts and parses a zip or tar.gz archive containing x-ui.db.
func ParseXUIArchive(archivePath string) (*XUIModel, error) {
	lower := strings.ToLower(archivePath)
	if strings.HasSuffix(lower, ".zip") {
		return parseZipArchive(archivePath)
	}
	if strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
		return parseTarGzArchive(archivePath)
	}
	return nil, errors.New("unsupported archive format, expected .zip or .tar.gz")
}

func parseZipArchive(zipPath string) (*XUIModel, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	tmpDir, err := os.MkdirTemp("", "relaydock-xui-zip-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	var foundDB string
	var totalBytes int64

	for i, f := range r.File {
		if i > maxArchiveFiles {
			return nil, errors.New("archive contains too many files")
		}
		if f.FileInfo().IsDir() {
			continue
		}
		name := filepath.Base(f.Name)
		if strings.HasSuffix(strings.ToLower(name), ".db") {
			target := filepath.Join(tmpDir, name)
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				rc.Close()
				return nil, err
			}
			n, err := io.Copy(out, io.LimitReader(rc, maxExtractBytes-totalBytes+1))
			rc.Close()
			out.Close()
			if err != nil {
				return nil, err
			}
			totalBytes += n
			if totalBytes > maxExtractBytes {
				return nil, errors.New("extracted size exceeds safety limit")
			}
			foundDB = target
			break
		}
	}

	if foundDB == "" {
		return nil, errors.New("no .db file found in zip archive")
	}

	return ParseXUIDatabase(foundDB)
}

func parseTarGzArchive(tarPath string) (*XUIModel, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return nil, fmt.Errorf("open tar.gz: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	tmpDir, err := os.MkdirTemp("", "relaydock-xui-tar-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	var foundDB string
	var totalBytes int64
	entries := 0

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		entries++
		if entries > maxArchiveFiles {
			return nil, errors.New("archive contains too many files")
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		name := filepath.Base(header.Name)
		if strings.HasSuffix(strings.ToLower(name), ".db") {
			target := filepath.Join(tmpDir, name)
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				return nil, err
			}
			n, err := io.Copy(out, io.LimitReader(tr, maxExtractBytes-totalBytes+1))
			out.Close()
			if err != nil {
				return nil, err
			}
			totalBytes += n
			if totalBytes > maxExtractBytes {
				return nil, errors.New("extracted size exceeds safety limit")
			}
			foundDB = target
			break
		}
	}

	if foundDB == "" {
		return nil, errors.New("no .db file found in tar.gz archive")
	}

	return ParseXUIDatabase(foundDB)
}

// ParseXUIInput safely attempts parsing from raw content or file path.
func ParseXUIInput(pathOrContent string) (*XUIModel, error) {
	trimmed := strings.TrimSpace(pathOrContent)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return ParseXUIJSON([]byte(trimmed))
	}
	// Check if file exists
	if fi, err := os.Stat(trimmed); err == nil && !fi.IsDir() {
		lower := strings.ToLower(trimmed)
		if strings.HasSuffix(lower, ".db") || strings.HasSuffix(lower, ".sqlite") {
			return ParseXUIDatabase(trimmed)
		}
		if strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".tar.gz") || strings.HasSuffix(lower, ".tgz") {
			return ParseXUIArchive(trimmed)
		}
		// Try reading as JSON file
		data, err := os.ReadFile(trimmed)
		if err == nil {
			return ParseXUIJSON(data)
		}
	}
	return nil, errors.New("input is neither valid JSON nor readable 3x-ui database file")
}
