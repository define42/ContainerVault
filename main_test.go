package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCvRouterRootRedirectsToLogin(t *testing.T) {
	router := cvRouter()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Fatalf("expected redirect to /login, got %q", loc)
	}
}

func TestCvRouterLoginGet(t *testing.T) {
	router := cvRouter()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<form") {
		t.Fatalf("expected login form in response")
	}
}

func TestCvRouterApiRequiresSession(t *testing.T) {
	resetSessions(t)
	router := cvRouter()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestCvRouterStaticSetsNoCache(t *testing.T) {
	staticDir := "static"
	_, err := os.Stat(staticDir)
	dirExisted := err == nil
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("stat static dir: %v", err)
	}
	if err := os.MkdirAll(staticDir, 0o755); err != nil {
		t.Fatalf("mkdir static dir: %v", err)
	}
	staticFile := filepath.Join(staticDir, "test.css")
	if err := os.WriteFile(staticFile, []byte("body{}"), 0o600); err != nil {
		t.Fatalf("write static file: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(staticFile)
		if !dirExisted {
			_ = os.Remove(staticDir)
		}
	})

	router := cvRouter()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/static/test.css", nil)

	router.ServeHTTP(rec, req)

	if rec.Header().Get("Cache-Control") == "" {
		t.Fatalf("expected Cache-Control header to be set, got headers: %#v", rec.Header())
	}
}

func TestCvRouterProxyForwards(t *testing.T) {
	originalAuth := ldapAuth
	ldapAuth = func(username, password string) (*User, error) {
		return &User{Name: username, Namespace: "team1"}, nil
	}
	t.Cleanup(func() {
		ldapAuth = originalAuth
	})

	originalUpstream := upstream
	upstream = mustParse("http://registry.test")
	t.Cleanup(func() {
		upstream = originalUpstream
	})

	originalTransport := proxyTransport
	t.Cleanup(func() {
		proxyTransport = originalTransport
	})

	var gotPath, gotAuth, gotXFF, gotHost string
	proxyTransport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotXFF = r.Header.Get("X-Forwarded-For")
		gotHost = r.Host
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("ok")),
			Request:    r,
		}, nil
	})

	router := cvRouter()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v2/team1/app/manifests/latest", nil)
	req.SetBasicAuth("alice", "secret")
	req.RemoteAddr = "192.0.2.10:1234"

	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if gotPath != "/v2/team1/app/manifests/latest" {
		t.Fatalf("expected upstream path, got %q", gotPath)
	}
	if gotAuth != "" {
		t.Fatalf("expected Authorization to be stripped, got %q", gotAuth)
	}
	if gotXFF == "" {
		t.Fatalf("expected X-Forwarded-For to be set")
	}
	if gotHost != upstream.Host {
		t.Fatalf("expected Host %q, got %q", upstream.Host, gotHost)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return fn(r)
}
