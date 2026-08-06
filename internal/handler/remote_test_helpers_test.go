package handler

import (
	"context"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/violetaini/relaydock/internal/storage"
)

func newRemoteHandlerTestRepo(t *testing.T) *storage.TrafficRepository {
	t.Helper()
	repo, err := storage.NewTrafficRepository(filepath.Join(t.TempDir(), "remote-handler.db"))
	if err != nil {
		t.Fatalf("NewTrafficRepository: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	return repo
}

func remoteAgentTestPort(t *testing.T, rawURL string) int {
	t.Helper()
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	_, portText, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func createRemoteHandlerTestServer(t *testing.T, repo *storage.TrafficRepository, name, agentURL string) *storage.RemoteServer {
	t.Helper()
	server := &storage.RemoteServer{
		Name:           name,
		Token:          name + "-token",
		Status:         storage.RemoteServerStatusConnected,
		ConnectionMode: storage.ConnectionModePush,
		IPAddress:      "127.0.0.1",
		IPv6Enabled:    true,
		ListenPort:     remoteAgentTestPort(t, agentURL),
	}
	if err := repo.CreateRemoteServer(context.Background(), server); err != nil {
		t.Fatalf("CreateRemoteServer(%s): %v", name, err)
	}
	return server
}
