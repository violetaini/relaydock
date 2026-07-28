package secretbox

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestBoxRoundTripUsesRandomNonceAndAssociatedData(t *testing.T) {
	box, err := New(bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	first, err := box.Seal([]byte("wireguard-private-key"), []byte("node:1"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := box.Seal([]byte("wireguard-private-key"), []byte("node:1"))
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !strings.HasPrefix(first, "v1:") {
		t.Fatalf("unexpected envelopes: %q %q", first, second)
	}
	plaintext, err := box.Open(first, []byte("node:1"))
	if err != nil || string(plaintext) != "wireguard-private-key" {
		t.Fatalf("round trip plaintext=%q err=%v", plaintext, err)
	}
	if _, err := box.Open(first, []byte("node:2")); err == nil {
		t.Fatal("associated data mismatch was accepted")
	}
}

func TestBoxRejectsWrongKeyAndTampering(t *testing.T) {
	box, _ := New(bytes.Repeat([]byte{0x11}, 32))
	other, _ := New(bytes.Repeat([]byte{0x22}, 32))
	envelope, err := box.Seal([]byte("secret"), []byte("node:7"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Open(envelope, []byte("node:7")); err == nil {
		t.Fatal("wrong key was accepted")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(envelope, "v1:"))
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01
	tampered := "v1:" + base64.RawURLEncoding.EncodeToString(raw)
	if _, err := box.Open(tampered, []byte("node:7")); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
}
