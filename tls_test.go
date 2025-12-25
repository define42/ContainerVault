package main

import (
	"os"
	"path/filepath"
	"testing"
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
