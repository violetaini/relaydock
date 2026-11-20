package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
)

func TestForwardNodeTargetsUseDestinationAndCredentials(t *testing.T) {
	ctx := context.Background()
	repo, err := NewTrafficRepository(filepath.Join(t.TempDir(), "forward-view.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err := repo.CreateUser(ctx, "admin", "", "", "fixture", RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	server := RemoteServer{Name: "entry", Token: "fixture-token", Status: RemoteServerStatusConnected, IPAddress: "203.0.113.5"}
	if err := repo.CreateRemoteServer(ctx, &server); err != nil {
		t.Fatal(err)
	}
	create := func(name, host, tag, password string, forward bool) Node {
		t.Helper()
		cfg := map[string]any{"name": name, "server": host, "port": 443, "type": "ss", "cipher": "2022-blake3-aes-128-gcm", "password": password}
		if !forward {
			cfg[ManagedShadowsocksMultiUserMarker] = true
		}
		b, _ := json.Marshal(cfg)
		n, err := repo.CreateNode(ctx, Node{Username: "admin", NodeName: name, Protocol: "shadowsocks", ClashConfig: string(b), ParsedConfig: string(b), Enabled: true, OriginalServer: server.Name, InboundTag: tag})
		if err != nil {
			t.Fatal(err)
		}
		if forward {
			if err := repo.MarkNodeForwarded(ctx, n.ID); err != nil {
				t.Fatal(err)
			}
			inbound := `{"protocol":"tunnel","port":443,"settings":{"address":"target.example.test","port":443,"network":"tcp,udp"}}`
			if _, err := repo.db.ExecContext(ctx, `INSERT INTO remote_inbound_desired(server_id,inbound_tag,mutation_id,inbound_json,desired_state) VALUES(?,?,?,?,'active')`, server.ID, tag, "fixture-"+tag, inbound); err != nil {
				t.Fatal(err)
			}
		}
		return n
	}
	source := create("renamed source", "target.example.test", "source", "credential-a", false)
	create("same endpoint, different credentials", "target.example.test", "other", "credential-b", false)
	custom := create("unrelated display name", "203.0.113.5", "custom-entry", "credential-a", true)
	matches, err := repo.ForwardNodeTargets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if matches[custom.ID] != source.ID {
		t.Fatalf("custom tag target %v", matches)
	}
	create("duplicate source", "target.example.test", "duplicate", "credential-a", false)
	matches, err = repo.ForwardNodeTargets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := matches[custom.ID]; ok {
		t.Fatal("ambiguous target was guessed")
	}
	hinted := create("hinted entry", "203.0.113.5", fmt.Sprintf("anydoor-node-%d", source.ID), "credential-a", true)
	matches, err = repo.ForwardNodeTargets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if matches[hinted.ID] != source.ID {
		t.Fatalf("validated hint target %v", matches)
	}
	if _, err := repo.db.ExecContext(ctx, `UPDATE remote_inbound_desired SET inbound_json='invalid json' WHERE inbound_tag=?`, hinted.InboundTag); err != nil {
		t.Fatal(err)
	}
	matches, err = repo.ForwardNodeTargets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := matches[hinted.ID]; ok {
		t.Fatal("invalid desired configuration was matched")
	}
}
