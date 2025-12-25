package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/certmagic"
)

func TestEnsureTLSCertCreatesFiles(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "registry.crt")
	keyPath := filepath.Join(dir, "registry.key")

	if err := ensureTLSCert(certPath, keyPath); err != nil {
		t.Fatalf("ensureTLSCert: %v", err)
	}

	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("expected cert file, got %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected key file, got %v", err)
	}

	if err := ensureTLSCert(certPath, keyPath); err != nil {
		t.Fatalf("ensureTLSCert again: %v", err)
	}
}

func TestLoadCertmagicConfigDisabled(t *testing.T) {
	t.Setenv("CERTMAGIC_ENABLE", "")
	t.Setenv("CERTMAGIC_DOMAINS", "")

	_, enabled, err := loadCertmagicConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if enabled {
		t.Fatalf("expected certmagic disabled")
	}
}

func TestLoadCertmagicConfigRequiresDomains(t *testing.T) {
	t.Setenv("CERTMAGIC_ENABLE", "true")
	t.Setenv("CERTMAGIC_DOMAINS", "")

	_, enabled, err := loadCertmagicConfig()
	if err == nil {
		t.Fatalf("expected error for missing domains")
	}
	if enabled {
		t.Fatalf("expected certmagic disabled on error")
	}
}

func TestLoadCertmagicConfigParsing(t *testing.T) {
	t.Setenv("CERTMAGIC_DOMAINS", "example.com, registry.example.com ")
	t.Setenv("CERTMAGIC_EMAIL", "ops@example.com")
	t.Setenv("CERTMAGIC_CA", "https://acme.local/directory")
	t.Setenv("CERTMAGIC_HTTP_PORT", "8080")
	t.Setenv("CERTMAGIC_TLS_ALPN_PORT", "8443")

	cfg, enabled, err := loadCertmagicConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !enabled {
		t.Fatalf("expected certmagic enabled")
	}
	if len(cfg.Domains) != 2 || cfg.Domains[0] != "example.com" || cfg.Domains[1] != "registry.example.com" {
		t.Fatalf("unexpected domains: %v", cfg.Domains)
	}
	if cfg.Email != "ops@example.com" || cfg.CA != "https://acme.local/directory" {
		t.Fatalf("unexpected config: %#v", cfg)
	}
	if cfg.AltHTTPPort != 8080 || cfg.AltTLSALPNPort != 8443 {
		t.Fatalf("unexpected ports: %#v", cfg)
	}
}

func TestCertmagicTLSConfigDisabled(t *testing.T) {
	t.Setenv("CERTMAGIC_ENABLE", "")
	t.Setenv("CERTMAGIC_DOMAINS", "")

	cfg, enabled, err := certmagicTLSConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if enabled {
		t.Fatalf("expected certmagic disabled")
	}
	if cfg != nil {
		t.Fatalf("expected nil tls config")
	}
}

func TestCertmagicTLSConfigCARootError(t *testing.T) {
	restoreCertmagicDefaults(t)
	t.Setenv("CERTMAGIC_ENABLE", "true")
	t.Setenv("CERTMAGIC_DOMAINS", "example.com")
	t.Setenv("CERTMAGIC_CA_ROOT", filepath.Join(t.TempDir(), "missing.pem"))

	cfg, enabled, err := certmagicTLSConfig()
	if err == nil {
		t.Fatalf("expected error for missing CA root")
	}
	if !enabled {
		t.Fatalf("expected certmagic enabled")
	}
	if cfg != nil {
		t.Fatalf("expected nil tls config")
	}
}

func TestCertmagicTLSConfigAppliesCARootAndStorage(t *testing.T) {
	restoreCertmagicDefaults(t)
	certDir := t.TempDir()
	certPath := filepath.Join(certDir, "root.pem")
	keyPath := filepath.Join(certDir, "root.key")
	if err := generateSelfSigned(certPath, keyPath); err != nil {
		t.Fatalf("generate self-signed: %v", err)
	}

	storagePath := filepath.Join(t.TempDir(), "certmagic")

	t.Setenv("CERTMAGIC_ENABLE", "true")
	t.Setenv("CERTMAGIC_DOMAINS", "example.com")
	t.Setenv("CERTMAGIC_CA_ROOT", certPath)
	t.Setenv("CERTMAGIC_STORAGE", storagePath)

	origTLS := certmagicTLS
	certmagicTLS = func(domains []string) (*tls.Config, error) {
		if len(domains) != 1 || domains[0] != "example.com" {
			t.Fatalf("unexpected domains: %v", domains)
		}
		return &tls.Config{}, nil
	}
	t.Cleanup(func() {
		certmagicTLS = origTLS
	})

	cfg, enabled, err := certmagicTLSConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !enabled {
		t.Fatalf("expected certmagic enabled")
	}
	if cfg == nil {
		t.Fatalf("expected tls config")
	}

	storage, ok := certmagic.Default.Storage.(*certmagic.FileStorage)
	if !ok {
		t.Fatalf("expected file storage, got %T", certmagic.Default.Storage)
	}
	if storage.Path != storagePath {
		t.Fatalf("expected storage path %q, got %q", storagePath, storage.Path)
	}

	roots := certmagic.DefaultACME.TrustedRoots
	if roots == nil {
		t.Fatalf("expected trusted roots")
	}

	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read CA root: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("expected PEM block in %s", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	found := false
	for _, subject := range roots.Subjects() {
		if bytes.Equal(subject, cert.RawSubject) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected CA root to be added to trusted pool")
	}
}

func restoreCertmagicDefaults(t *testing.T) {
	t.Helper()
	prevEmail := certmagic.DefaultACME.Email
	prevCA := certmagic.DefaultACME.CA
	prevAltHTTP := certmagic.DefaultACME.AltHTTPPort
	prevAltTLS := certmagic.DefaultACME.AltTLSALPNPort
	prevRoots := certmagic.DefaultACME.TrustedRoots
	prevStorage := certmagic.Default.Storage

	t.Cleanup(func() {
		certmagic.DefaultACME.Email = prevEmail
		certmagic.DefaultACME.CA = prevCA
		certmagic.DefaultACME.AltHTTPPort = prevAltHTTP
		certmagic.DefaultACME.AltTLSALPNPort = prevAltTLS
		certmagic.DefaultACME.TrustedRoots = prevRoots
		certmagic.Default.Storage = prevStorage
	})
}
