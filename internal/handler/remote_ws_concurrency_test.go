package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/violetaini/relaydock/internal/securechan"

	"github.com/gorilla/websocket"
)

func TestSendEncryptedMessageSerializesConcurrentWriters(t *testing.T) {
	for _, tc := range []struct {
		name      string
		encrypted bool
	}{
		{name: "encrypted", encrypted: true},
		{name: "plaintext", encrypted: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testConcurrentRemoteWSSends(t, tc.encrypted)
		})
	}
}

func testConcurrentRemoteWSSends(t *testing.T, encrypted bool) {
	t.Helper()

	serverConnCh := make(chan *websocket.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serverConnCh <- conn
	}))
	defer server.Close()

	clientConn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer clientConn.Close()
	serverConn := <-serverConnCh
	defer serverConn.Close()

	var masterSession, agentSession *securechan.Session
	if encrypted {
		masterSession, agentSession = newTestSecureSessions(t)
	}

	const messageCount = 48
	readErrCh := make(chan error, 1)
	go func() {
		_ = serverConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		seen := make(map[int]bool, messageCount)
		for range messageCount {
			messageType, wireData, readErr := serverConn.ReadMessage()
			if readErr != nil {
				readErrCh <- readErr
				return
			}
			expectedType := websocket.TextMessage
			plaintext := wireData
			if encrypted {
				expectedType = websocket.BinaryMessage
				var decryptErr error
				plaintext, decryptErr = agentSession.Decrypt(wireData)
				if decryptErr != nil {
					readErrCh <- decryptErr
					return
				}
			}
			if messageType != expectedType {
				readErrCh <- fmt.Errorf("unexpected message type %d", messageType)
				return
			}
			var msg WSMessage
			if unmarshalErr := json.Unmarshal(plaintext, &msg); unmarshalErr != nil {
				readErrCh <- unmarshalErr
				return
			}
			var payload struct {
				ID int `json:"id"`
			}
			if unmarshalErr := json.Unmarshal(msg.Payload, &payload); unmarshalErr != nil {
				readErrCh <- unmarshalErr
				return
			}
			seen[payload.ID] = true
		}
		if len(seen) != messageCount {
			readErrCh <- fmt.Errorf("received %d unique messages, want %d", len(seen), messageCount)
			return
		}
		readErrCh <- nil
	}()

	wsConn := &RemoteWSConnection{Conn: clientConn, session: masterSession, Encrypted: true}
	handler := &RemoteWSHandler{}
	start := make(chan struct{})
	errCh := make(chan error, messageCount)
	var writers sync.WaitGroup
	for i := range messageCount {
		writers.Add(1)
		go func(id int) {
			defer writers.Done()
			<-start
			payload, marshalErr := json.Marshal(map[string]int{"id": id})
			if marshalErr != nil {
				errCh <- marshalErr
				return
			}
			errCh <- handler.sendEncryptedMessage(wsConn, WSMessage{Type: "concurrency_test", Payload: payload})
		}(i)
	}
	close(start)
	writers.Wait()
	close(errCh)
	for writeErr := range errCh {
		if writeErr != nil {
			t.Fatalf("send encrypted message: %v", writeErr)
		}
	}
	if readErr := <-readErrCh; readErr != nil {
		t.Fatalf("read encrypted messages: %v", readErr)
	}
}

func newTestSecureSessions(t *testing.T) (*securechan.Session, *securechan.Session) {
	t.Helper()

	agentPriv, agentPub, err := securechan.GenerateEphemeral()
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	masterPriv, masterPub, err := securechan.GenerateEphemeral()
	if err != nil {
		t.Fatalf("generate master key: %v", err)
	}
	masterSecret, err := securechan.ComputeSharedSecret(masterPriv, agentPub)
	if err != nil {
		t.Fatalf("derive master shared secret: %v", err)
	}
	agentSecret, err := securechan.ComputeSharedSecret(agentPriv, masterPub)
	if err != nil {
		t.Fatalf("derive agent shared secret: %v", err)
	}
	masterSession, err := securechan.DeriveSession(masterSecret, agentPub, masterPub, true)
	if err != nil {
		t.Fatalf("derive master session: %v", err)
	}
	agentSession, err := securechan.DeriveSession(agentSecret, agentPub, masterPub, false)
	if err != nil {
		t.Fatalf("derive agent session: %v", err)
	}
	return masterSession, agentSession
}
