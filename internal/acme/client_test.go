package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProcessCertResultValidatesAndAtomicallyStoresPair(t *testing.T) {
	certPEM, keyPEM := testCertificatePair(t, "cert.example.test")
	certDir := t.TempDir()
	client := NewClient(WithCertDir(certDir))
	result, err := client.ProcessCertResult("cert.example.test", certPEM, keyPEM)
	if err != nil {
		t.Fatalf("ProcessCertResult: %v", err)
	}
	if result.CertPath != filepath.Join(certDir, "cert.example.test", "fullchain.pem") ||
		result.KeyPath != filepath.Join(certDir, "cert.example.test", "privkey.pem") {
		t.Fatalf("unexpected stored paths: %#v", result)
	}
	assertFileContent(t, result.CertPath, string(certPEM))
	assertFileContent(t, result.KeyPath, string(keyPEM))
}

func TestProcessCertResultRejectsMismatchedPrivateKeyWithoutWriting(t *testing.T) {
	certPEM, _ := testCertificatePair(t, "cert.example.test")
	_, otherKey := testCertificatePair(t, "other.example.test")
	certDir := t.TempDir()
	client := NewClient(WithCertDir(certDir))
	if _, err := client.ProcessCertResult("cert.example.test", certPEM, otherKey); err == nil || !strings.Contains(err.Error(), "private key") {
		t.Fatalf("expected key mismatch, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(certDir, "cert.example.test")); !os.IsNotExist(err) {
		t.Fatalf("invalid pair created storage directory: %v", err)
	}
}

func TestProcessCertResultRejectsDomainPathTraversal(t *testing.T) {
	certPEM, keyPEM := testCertificatePair(t, "cert.example.test")
	client := NewClient(WithCertDir(t.TempDir()))
	if _, err := client.ProcessCertResult("../../outside", certPEM, keyPEM); err == nil || !strings.Contains(err.Error(), "invalid certificate domain") {
		t.Fatalf("expected unsafe domain rejection, got %v", err)
	}
}

func testCertificatePair(t *testing.T, domain string) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}
