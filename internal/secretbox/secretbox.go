package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const (
	envelopePrefix = "v1:"
	keyPurpose     = "arcway-node-secrets-v1"
)

// Box encrypts database secrets with a key derived from the panel master key.
// Each value uses a fresh random AES-GCM nonce and caller-provided associated
// data, so ciphertext cannot be moved between database records undetected.
type Box struct {
	aead cipher.AEAD
}

func New(masterKey []byte) (*Box, error) {
	if len(masterKey) < 32 {
		return nil, errors.New("secretbox master key must contain at least 32 bytes")
	}
	key := make([]byte, 32)
	reader := hkdf.New(sha256.New, masterKey, nil, []byte(keyPurpose))
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("derive secretbox key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create secretbox cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create secretbox gcm: %w", err)
	}
	return &Box{aead: aead}, nil
}

func (b *Box) Seal(plaintext []byte, associatedData []byte) (string, error) {
	if b == nil || b.aead == nil {
		return "", errors.New("secretbox is not configured")
	}
	if len(plaintext) == 0 {
		return "", errors.New("secretbox plaintext is empty")
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate secretbox nonce: %w", err)
	}
	envelope := append(nonce, b.aead.Seal(nil, nonce, plaintext, associatedData)...)
	return envelopePrefix + base64.RawURLEncoding.EncodeToString(envelope), nil
}

func (b *Box) Open(envelope string, associatedData []byte) ([]byte, error) {
	if b == nil || b.aead == nil {
		return nil, errors.New("secretbox is not configured")
	}
	if !strings.HasPrefix(envelope, envelopePrefix) {
		return nil, errors.New("unsupported secretbox envelope version")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(envelope, envelopePrefix))
	if err != nil {
		return nil, fmt.Errorf("decode secretbox envelope: %w", err)
	}
	nonceSize := b.aead.NonceSize()
	if len(raw) < nonceSize+b.aead.Overhead() {
		return nil, errors.New("secretbox envelope is truncated")
	}
	plaintext, err := b.aead.Open(nil, raw[:nonceSize], raw[nonceSize:], associatedData)
	if err != nil {
		return nil, errors.New("decrypt secretbox envelope")
	}
	return plaintext, nil
}
