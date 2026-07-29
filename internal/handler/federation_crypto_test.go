package handler

import (
	"bytes"
	"testing"

	"github.com/violetaini/relaydock/internal/securechan"
)

// 验证令牌揭示的 ECDH:双方各自临时密钥对 + 相同分享令牌,应派生出可互通的会话。
func TestFederationSessionRoundTrip(t *testing.T) {
	const token = "share-token-abc123"

	consPriv, consPub, err := securechan.GenerateEphemeral()
	if err != nil {
		t.Fatalf("consumer ephemeral: %v", err)
	}
	ownerPriv, ownerPub, err := securechan.GenerateEphemeral()
	if err != nil {
		t.Fatalf("owner ephemeral: %v", err)
	}

	consSession, err := deriveFederationSession(consPriv, ownerPub, consPub, token, true)
	if err != nil {
		t.Fatalf("consumer session: %v", err)
	}
	ownerSession, err := deriveFederationSession(ownerPriv, ownerPub, consPub, token, false)
	if err != nil {
		t.Fatalf("owner session: %v", err)
	}

	// 消费方 → 拥有方
	plaintext := []byte(`{"method":"GET","path":"/api/child/inbounds"}`)
	enc, err := consSession.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("consumer encrypt: %v", err)
	}
	dec, err := ownerSession.Decrypt(enc)
	if err != nil {
		t.Fatalf("owner decrypt: %v", err)
	}
	if !bytes.Equal(dec, plaintext) {
		t.Fatalf("c2o mismatch: got %q want %q", dec, plaintext)
	}

	// 拥有方 → 消费方
	resp := []byte(`{"success":true}`)
	enc2, err := ownerSession.Encrypt(resp)
	if err != nil {
		t.Fatalf("owner encrypt: %v", err)
	}
	dec2, err := consSession.Decrypt(enc2)
	if err != nil {
		t.Fatalf("consumer decrypt: %v", err)
	}
	if !bytes.Equal(dec2, resp) {
		t.Fatalf("o2c mismatch: got %q want %q", dec2, resp)
	}
}

// 令牌不一致时不应能解密(令牌揭示鉴权).
func TestFederationSessionTokenMismatch(t *testing.T) {
	consPriv, consPub, _ := securechan.GenerateEphemeral()
	ownerPriv, ownerPub, _ := securechan.GenerateEphemeral()

	consSession, err := deriveFederationSession(consPriv, ownerPub, consPub, "token-A", true)
	if err != nil {
		t.Fatalf("consumer session: %v", err)
	}
	ownerSession, err := deriveFederationSession(ownerPriv, ownerPub, consPub, "token-B", false)
	if err != nil {
		t.Fatalf("owner session: %v", err)
	}

	enc, err := consSession.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := ownerSession.Decrypt(enc); err == nil {
		t.Fatal("expected decrypt to fail with mismatched token")
	}
}
