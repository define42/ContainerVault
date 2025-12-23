package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestExtractCredentialsBasicAuth(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.SetBasicAuth("alice", "secret")
	user, pass, ok, err := extractCredentials(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok || user != "alice" || pass != "secret" {
		t.Fatalf("unexpected credentials: %v %v %t", user, pass, ok)
	}
}

func TestExtractCredentialsForm(t *testing.T) {
	form := url.Values{}
	form.Set("username", "bob")
	form.Set("password", "hunter2")
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	user, pass, ok, err := extractCredentials(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok || user != "bob" || pass != "hunter2" {
		t.Fatalf("unexpected credentials: %v %v %t", user, pass, ok)
	}
}

func TestHandleLoginGet(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	handleLogin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<form") {
		t.Fatalf("expected login form in response")
	}
	if rec.Header().Get("Cache-Control") == "" {
		t.Fatalf("expected cache-control header")
	}
}

func TestHandleLoginMissingCredentials(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	handleLogin(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Missing credentials.") {
		t.Fatalf("expected missing credentials error")
	}
}

func TestHandleLogoutClearsSession(t *testing.T) {
	token := seedSession(t, "alice", []string{"team1"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "cv_session", Value: token})
	handleLogout(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Set-Cookie"), "cv_session=") {
		t.Fatalf("expected session cookie to be cleared")
	}

	sessionMu.Lock()
	_, exists := sessions[token]
	sessionMu.Unlock()
	if exists {
		t.Fatalf("expected session to be removed")
	}
}

func TestHandleLogoutMethodNotAllowed(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	handleLogout(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d", rec.Code)
	}
}

func TestServeDashboardUnauthorized(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	Session(serveDashboard).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestServeDashboardOK(t *testing.T) {
	token := seedSession(t, "alice", []string{"team1", "team2"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "cv_session", Value: token})

	Session(serveDashboard).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Welcome, alice") {
		t.Fatalf("expected username in dashboard")
	}
	if !strings.Contains(body, `"namespaces":["team1","team2"]`) {
		t.Fatalf("expected namespaces in bootstrap")
	}
	if rec.Header().Get("Cache-Control") == "" {
		t.Fatalf("expected cache-control header")
	}
}

func TestHandleCatalogSuccess(t *testing.T) {
	cleanup := withUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/_catalog":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"repositories":["team1/app"]}`))
		case "/v2/team1/app/tags/list":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"name":"team1/app","tags":["v1"]}`))
		default:
			http.NotFound(w, r)
		}
	})
	defer cleanup()

	token := seedSession(t, "alice", []string{"team1"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/catalog?namespace=team1", nil)
	req.AddCookie(&http.Cookie{Name: "cv_session", Value: token})
	Session(handleCatalog).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var payload struct {
		Username     string     `json:"username"`
		Namespace    string     `json:"namespace"`
		Repositories []repoInfo `json:"repositories"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Username != "alice" || payload.Namespace != "team1" || len(payload.Repositories) != 1 {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestHandleCatalogNamespaceNotAllowed(t *testing.T) {
	token := seedSession(t, "alice", []string{"team1"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/catalog?namespace=team2", nil)
	req.AddCookie(&http.Cookie{Name: "cv_session", Value: token})
	sess := sessionFromRequest(t, req)
	handleCatalog(rec, req, sess)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestHandleReposSuccess(t *testing.T) {
	cleanup := withUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/_catalog" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"repositories":["team1/app","team2/skip"]}`))
	})
	defer cleanup()

	token := seedSession(t, "alice", []string{"team1"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/repos?namespace=team1", nil)
	req.AddCookie(&http.Cookie{Name: "cv_session", Value: token})
	Session(handleRepos).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var payload struct {
		Namespace    string   `json:"namespace"`
		Repositories []string `json:"repositories"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Namespace != "team1" || len(payload.Repositories) != 1 || payload.Repositories[0] != "team1/app" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestHandleTagsSuccess(t *testing.T) {
	cleanup := withUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/team1/app/tags/list" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"team1/app","tags":["v1","v2"]}`))
	})
	defer cleanup()

	token := seedSession(t, "alice", []string{"team1"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/tags?repo=team1/app", nil)
	req.AddCookie(&http.Cookie{Name: "cv_session", Value: token})
	Session(handleTags).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var payload struct {
		Repo string   `json:"repo"`
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Repo != "team1/app" || len(payload.Tags) != 2 {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestHandleTagInfoSuccess(t *testing.T) {
	cleanup := withUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/team1/app/manifests/latest" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.Header().Set("Docker-Content-Digest", "sha256:abc")
		_, _ = w.Write([]byte(`{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "config": { "size": 2, "digest": "sha256:cfg", "mediaType": "application/vnd.docker.container.image.v1+json" },
  "layers": [
    { "size": 3, "digest": "sha256:a", "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip" }
  ]
}`))
	})
	defer cleanup()

	token := seedSession(t, "alice", []string{"team1"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/taginfo?repo=team1/app&tag=latest", nil)
	req.AddCookie(&http.Cookie{Name: "cv_session", Value: token})
	Session(handleTagInfo).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var info tagInfo
	if err := json.NewDecoder(rec.Body).Decode(&info); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if info.Digest != "sha256:abc" || info.Tag != "latest" || info.CompressedSize == 0 {
		t.Fatalf("unexpected tag info: %#v", info)
	}
}

func TestHandleTagLayersSuccess(t *testing.T) {
	cleanup := withUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/team1/app/manifests/latest":
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			w.Header().Set("Docker-Content-Digest", "sha256:manifest")
			_, _ = w.Write([]byte(`{
  "schemaVersion": 2,
  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
  "config": { "size": 2, "digest": "sha256:cfg", "mediaType": "application/vnd.docker.container.image.v1+json" },
  "layers": [
    { "size": 3, "digest": "sha256:a", "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip" }
  ]
}`))
		case "/v2/team1/app/blobs/sha256:cfg":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"created":"2024-01-01T00:00:00Z","os":"linux","architecture":"amd64","config":{"Entrypoint":[],"Cmd":[],"Env":[],"Labels":{}},"history":[]}`))
		default:
			http.NotFound(w, r)
		}
	})
	defer cleanup()

	token := seedSession(t, "alice", []string{"team1"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/taglayers?repo=team1/app&tag=latest", nil)
	req.AddCookie(&http.Cookie{Name: "cv_session", Value: token})
	Session(handleTagLayers).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var details tagDetails
	if err := json.NewDecoder(rec.Body).Decode(&details); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if details.Tag != "latest" || len(details.Layers) != 1 || details.Config.Digest != "sha256:cfg" {
		t.Fatalf("unexpected details: %#v", details)
	}
}

func seedSession(t *testing.T, userName string, namespaces []string) string {
	t.Helper()
	sessionMu.Lock()
	sessions = map[string]sessionData{}
	sessionMu.Unlock()
	t.Cleanup(func() {
		sessionMu.Lock()
		sessions = map[string]sessionData{}
		sessionMu.Unlock()
	})
	token := "token-" + userName
	sessionMu.Lock()
	sessions[token] = sessionData{
		User:       &User{Name: userName},
		Namespaces: namespaces,
		CreatedAt:  time.Now(),
	}
	sessionMu.Unlock()
	return token
}
