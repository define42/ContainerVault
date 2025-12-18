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
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

var (
	upstream = mustParse("http://registry:5000")
	ldapCfg  = loadLDAPConfig()
)

type User struct {
	Name          string
	Namespace     string
	PullOnly      bool
	DeleteAllowed bool
}

type LDAPConfig struct {
	URL             string
	BaseDN          string
	UserFilter      string
	GroupAttribute  string
	GroupNamePrefix string
	UserMailDomain  string
	StartTLS        bool
	SkipTLSVerify   bool
}

func main() {
	// Use single-host reverse proxy to forward traffic to the registry
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
		},
	}

	proxy.FlushInterval = -1 // important for streaming blobs

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/" {
			serveLanding(w)
			return
		}

		user, ok := authenticate(w, r)
		if !ok {
			fmt.Println("not working with user", user)
			return
		}

		if !authorize(user, r) {
			fmt.Println("forbidden", user.Name, r.Method, r.URL.Path, user)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		proxy.ServeHTTP(w, r)
	})

	certPath := "/certs/registry.crt"
	keyPath := "/certs/registry.key"

	if err := ensureTLSCert(certPath, keyPath); err != nil {
		log.Fatalf("unable to ensure TLS certificate: %v", err)
	}

	log.Println("listening on :8443")
	log.Fatal(http.ListenAndServeTLS(
		":8443",
		certPath,
		keyPath,
		handler,
	))
}

func authenticate(w http.ResponseWriter, r *http.Request) (*User, bool) {
	fmt.Println(r.Header)
	username, password, ok := r.BasicAuth()
	fmt.Println("sssssssssssssssss:", username)
	if !ok || password == "" {
		fmt.Println("write header WWW-Authenticate")
		w.Header().Set("WWW-Authenticate", `Basic realm="Registry"`)
		http.Error(w, "auth required", http.StatusUnauthorized)
		return nil, false
	}

	u, err := ldapAuthenticate(username, password)
	if err != nil {
		log.Printf("ldap auth failed for %s: %v", username, err)
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return nil, false
	}

	return u, true
}

func authorize(u *User, r *http.Request) bool {
	// Allow registry ping after authentication
	if r.URL.Path == "/v2/" {
		return true
	}

	// Path must be /v2/<namespace>/...
	prefix := "/v2/" + u.Namespace + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}

	// Pull-only enforcement
	if u.PullOnly {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			return true
		default:
			return false
		}
	}

	if r.Method == http.MethodDelete {
		return u.DeleteAllowed
	}

	return true
}

func mustParse(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// ensureTLSCert creates a self-signed cert/key pair if either file is missing.
func ensureTLSCert(certPath, keyPath string) error {
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
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
	if err := os.WriteFile(certPath, certOut, 0o644); err != nil {
		return err
	}

	keyOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	if err := os.WriteFile(keyPath, keyOut, 0o600); err != nil {
		return err
	}

	return nil
}

func loadLDAPConfig() LDAPConfig {
	return LDAPConfig{
		URL:             getEnv("LDAP_URL", "ldaps://ldap:389"),
		BaseDN:          getEnv("LDAP_BASE_DN", "dc=glauth,dc=com"),
		UserFilter:      getEnv("LDAP_USER_FILTER", "(uid=%s)"),
		GroupAttribute:  getEnv("LDAP_GROUP_ATTRIBUTE", "memberOf"),
		GroupNamePrefix: getEnv("LDAP_GROUP_PREFIX", "team"),
		UserMailDomain:  getEnv("LDAP_USER_DOMAIN", "@example.com"),
		StartTLS:        getEnvBool("LDAP_STARTTLS", false),
		SkipTLSVerify:   getEnvBool("LDAP_SKIP_TLS_VERIFY", true),
	}
}

func ldapAuthenticate(username, password string) (*User, error) {
	conn, err := dialLDAP(ldapCfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	mail := username
	if !strings.Contains(username, "@") && ldapCfg.UserMailDomain != "" {
		domain := ldapCfg.UserMailDomain
		if !strings.HasPrefix(domain, "@") {
			domain = "@" + domain
		}
		mail = username + domain
	}

	fmt.Println("my email", mail)

	// Bind as the user using only the mail/UPN form.
	bindIDs := []string{mail}

	var bindErr error
	for _, id := range bindIDs {
		if id == "" {
			continue
		}
		if err := conn.Bind(id, password); err == nil {
			bindErr = nil
			break
		} else {
			bindErr = err
		}
	}
	if bindErr != nil {
		return nil, fmt.Errorf("ldap bind failed: %w", bindErr)
	}
	fmt.Println("Bind gik godt for ", mail)
	/*
			userDN := ""
			if res, err := conn.WhoAmI(nil); err == nil {
				if dn := extractDN(res.AuthzID); dn != "" {
					userDN = dn
				}
			}
			fmt.Println("aaaaaaaaaaaaaaawho am i:", userDN)

		var entry *ldap.Entry
		if userDN != "" {
			entry, err = fetchEntry(conn, userDN, ldapCfg.GroupAttribute)
		}*/

	filter := fmt.Sprintf(ldapCfg.UserFilter, username)
	fmt.Println("filter", filter)
	searchReq := ldap.NewSearchRequest(
		ldapCfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 1, 0, false,
		filter,
		nil,
		nil,
	)

	sr, err := conn.Search(searchReq)
	if err != nil {
		fmt.Println("what", err)
		return nil, fmt.Errorf("ldap search: %w", err)
	}
	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("user %s not found", mail)
	}
	fmt.Println("############################", sr.Entries, len(sr.Entries))

	for _, e := range sr.Entries {
		fmt.Println("Entry DN:", e.DN)
		fmt.Println(GetUserGroups(conn, e.DN, ldapCfg.BaseDN))
		for _, attr := range e.Attributes {
			fmt.Printf("  %s: %v\n", attr.Name, attr.Values)
		}
	}

	entry := sr.Entries[0]

	groups := entry.GetAttributeValues(ldapCfg.GroupAttribute)
	fmt.Println("Groups for", username, ":", groups)
	user := userFromGroups(username, groups, ldapCfg.GroupNamePrefix)
	if user == nil {
		return nil, fmt.Errorf("no authorized groups for %s", username)
	}

	return user, nil
}

func fetchEntry(conn *ldap.Conn, dn string, groupAttr string) (*ldap.Entry, error) {
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{"dn", groupAttr},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil || len(res.Entries) == 0 {
		return nil, err
	}
	return res.Entries[0], nil
}

func extractDN(authzID string) string {
	authzID = strings.TrimSpace(authzID)
	if strings.HasPrefix(strings.ToLower(authzID), "dn:") {
		return strings.TrimSpace(authzID[3:])
	}
	if strings.Contains(authzID, "=") && strings.Contains(authzID, ",") {
		return authzID
	}
	return ""
}

func dialLDAP(cfg LDAPConfig) (*ldap.Conn, error) {
	conn, err := ldap.DialURL(cfg.URL, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify}))
	if err != nil {
		return nil, err
	}

	if cfg.StartTLS && strings.HasPrefix(cfg.URL, "ldap://") {
		if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: cfg.SkipTLSVerify}); err != nil {
			conn.Close()
			return nil, err
		}
	}

	return conn, nil
}

func userFromGroups(username string, groups []string, prefix string) *User {
	var selected *User

	for _, g := range groups {
		groupName := groupNameFromDN(g)
		fmt.Println("groupName", groupName, prefix)
		if prefix != "" && !strings.HasPrefix(groupName, prefix) {
			continue
		}
		fmt.Println("A")

		ns, pullOnly, deleteAllowed, ok := permissionsFromGroup(groupName)
		if !ok {
			continue
		}
		fmt.Println("B")

		candidate := &User{
			Name:          username,
			Namespace:     ns,
			PullOnly:      pullOnly,
			DeleteAllowed: deleteAllowed,
		}

		if selected == nil || morePermissive(candidate, selected) {
			selected = candidate
		}
		fmt.Println("C")
	}

	return selected
}

func groupNameFromDN(dn string) string {
	parts := strings.SplitN(dn, ",", 2)
	if len(parts) == 0 {
		return dn
	}

	first := strings.TrimSpace(parts[0])
	firstLower := strings.ToLower(first)

	switch {
	case strings.HasPrefix(firstLower, "cn="):
		return first[3:]
	case strings.HasPrefix(firstLower, "ou="):
		return first[3:]
	default:
		return dn
	}
}

func permissionsFromGroup(group string) (namespace string, pullOnly bool, deleteAllowed bool, ok bool) {
	switch {
	case strings.HasSuffix(group, "_read_write_delete"):
		ns := strings.TrimSuffix(group, "_read_write_delete")
		return ns, false, true, true
	case strings.HasSuffix(group, "_read_write"):
		ns := strings.TrimSuffix(group, "_read_write")
		return ns, false, false, true
	case strings.HasSuffix(group, "_read_only"):
		ns := strings.TrimSuffix(group, "_read_only")
		return ns, true, false, true
	default:
		// Bare group name defaults to read/write without delete
		return group, false, false, true
	}
}

func morePermissive(a, b *User) bool {
	if a.DeleteAllowed != b.DeleteAllowed {
		return a.DeleteAllowed
	}
	if a.PullOnly != b.PullOnly {
		return !a.PullOnly
	}
	return false
}

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

func getEnvBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		v = strings.ToLower(strings.TrimSpace(v))
		return v == "1" || v == "true" || v == "yes"
	}
	return def
}

func serveLanding(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, landingHTML)
}

const landingHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ContainerVault-Enterprise</title>
  <style>
    body { margin:0; font-family: "Segoe UI", sans-serif; background:#0f172a; color:#e2e8f0; display:flex; align-items:center; justify-content:center; min-height:100vh; }
    .card { background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08); border-radius:16px; padding:32px 36px; max-width:520px; box-shadow:0 20px 60px rgba(0,0,0,0.35); }
    h1 { margin:0 0 12px; font-size:32px; letter-spacing:0.5px; color:#38bdf8; }
    p { margin:8px 0; line-height:1.5; }
    .tag { display:inline-block; padding:6px 10px; border-radius:999px; background:rgba(56,189,248,0.12); color:#bae6fd; font-size:12px; letter-spacing:0.4px; text-transform:uppercase; }
    .mono { font-family: "SFMono-Regular", Consolas, monospace; color:#cbd5e1; }
  </style>
</head>
<body>
  <div class="card">
    <div class="tag">Container Registry Proxy</div>
    <h1>ContainerVault-Enterprise</h1>
    <p>Secure gateway for your private Docker registry with per-namespace access control.</p>
    <p class="mono">Push &amp; pull via this endpoint:<br> <strong>https://skod.net</strong></p>
    <p class="mono">Ping: <strong>GET /v2/</strong><br> Namespaced access: <strong>/v2/&lt;team&gt;/...</strong></p>
  </div>
</body>
</html>
`

func GetUserGroups(
	l *ldap.Conn,
	userDN string,
	baseDN string,

) ([]string, error) {

	//userDN := fmt.Sprintf("cn=%s,%s", username, baseDN)

	filter := fmt.Sprintf("(member=%s)", ldap.EscapeFilter(userDN))

	req := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"cn"},
		nil,
	)

	res, err := l.Search(req)
	if err != nil {
		return nil, err
	}

	var groups []string
	for _, entry := range res.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}

	return groups, nil
}

func FindUserDN(
	l *ldap.Conn,
	baseDN string,
	login string,
) (string, error) {

	filter := fmt.Sprintf(
		"(|(uid=%s)(cn=%s)(mail=%s))",
		ldap.EscapeFilter(login),
		ldap.EscapeFilter(login),
		ldap.EscapeFilter(login),
	)

	req := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		filter,
		[]string{}, // DN only
		nil,
	)

	res, err := l.Search(req)
	if err != nil {
		return "", err
	}

	if len(res.Entries) != 1 {
		return "", fmt.Errorf("user not found or ambiguous")
	}

	return res.Entries[0].DN, nil
}
