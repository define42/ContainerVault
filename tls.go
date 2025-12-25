package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
)

var certmagicTLS = certmagic.TLS

// ensureTLSCert creates a self-signed cert/key pair if either file is missing.
func ensureTLSCert(certPath, keyPath string) error {
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(certPath), 0o750); err != nil {
		return err
	}

	log.Printf("generating self-signed certificate at %s", certPath)
	return generateSelfSigned(certPath, keyPath)
}

func generateSelfSigned(certPath, keyPath string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "registry",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"registry", "localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err := os.WriteFile(certPath, certOut, 0o600); err != nil {
		return err
	}

	keyOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err := os.WriteFile(keyPath, keyOut, 0o600); err != nil {
		return err
	}

	return nil
}

type certmagicConfig struct {
	Domains        []string
	Email          string
	CA             string
	CARootPath     string
	StoragePath    string
	AltHTTPPort    int
	AltTLSALPNPort int
}

func certmagicTLSConfig() (*tls.Config, bool, error) {
	cfg, enabled, err := loadCertmagicConfig()
	if err != nil || !enabled {
		return nil, enabled, err
	}

	if cfg.Email != "" {
		certmagic.DefaultACME.Email = cfg.Email
	}
	if cfg.CA != "" {
		certmagic.DefaultACME.CA = cfg.CA
	}
	if cfg.AltTLSALPNPort == 0 {
		// Align ACME TLS-ALPN with the internal listener (443 -> 8443 mapping).
		cfg.AltTLSALPNPort = 8443
	}
	if cfg.AltHTTPPort != 0 {
		certmagic.DefaultACME.AltHTTPPort = cfg.AltHTTPPort
	}
	if cfg.AltTLSALPNPort != 0 {
		certmagic.DefaultACME.AltTLSALPNPort = cfg.AltTLSALPNPort
	}
	if cfg.CARootPath != "" {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		pemBytes, err := os.ReadFile(cfg.CARootPath)
		if err != nil {
			return nil, true, err
		}
		if ok := roots.AppendCertsFromPEM(pemBytes); !ok {
			return nil, true, fmt.Errorf("no certificates found in %s", cfg.CARootPath)
		}
		certmagic.DefaultACME.TrustedRoots = roots
	}
	if cfg.StoragePath != "" {
		certmagic.Default.Storage = &certmagic.FileStorage{Path: cfg.StoragePath}
	}

	tlsCfg, err := certmagicTLS(cfg.Domains)
	if err != nil {
		return nil, true, err
	}
	tlsCfg.NextProtos = append([]string{"h2", "http/1.1"}, tlsCfg.NextProtos...)
	return tlsCfg, true, nil
}

func loadCertmagicConfig() (certmagicConfig, bool, error) {
	domains := splitCommaList(os.Getenv("CERTMAGIC_DOMAINS"))
	enabled := getEnvBool("CERTMAGIC_ENABLE", false)
	if !enabled && len(domains) == 0 {
		return certmagicConfig{}, false, nil
	}
	if len(domains) == 0 {
		return certmagicConfig{}, false, fmt.Errorf("CERTMAGIC_DOMAINS must be set when certmagic is enabled")
	}

	cfg := certmagicConfig{
		Domains:     domains,
		Email:       strings.TrimSpace(os.Getenv("CERTMAGIC_EMAIL")),
		CA:          strings.TrimSpace(os.Getenv("CERTMAGIC_CA")),
		CARootPath:  strings.TrimSpace(os.Getenv("CERTMAGIC_CA_ROOT")),
		StoragePath: strings.TrimSpace(os.Getenv("CERTMAGIC_STORAGE")),
	}

	var err error
	cfg.AltHTTPPort, err = parseEnvPort("CERTMAGIC_HTTP_PORT")
	if err != nil {
		return certmagicConfig{}, false, err
	}
	cfg.AltTLSALPNPort, err = parseEnvPort("CERTMAGIC_TLS_ALPN_PORT")
	if err != nil {
		return certmagicConfig{}, false, err
	}

	return cfg, true, nil
}

func splitCommaList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func parseEnvPort(key string) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return 0, nil
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("invalid %s: %q", key, raw)
	}
	return port, nil
}
