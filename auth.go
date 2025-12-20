package main

import (
	"net/http"
	"strings"
)

var ldapAuth = ldapAuthenticate

func authenticate(w http.ResponseWriter, r *http.Request) (*User, bool) {
	username, password, ok := r.BasicAuth()
	if !ok || password == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="Registry"`)
		http.Error(w, "auth required", http.StatusUnauthorized)
		return nil, false
	}

	u, err := ldapAuth(username, password)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return nil, false
	}

	return u, true
}

func authorize(u *User, r *http.Request) bool {
	if !isSafeRequestPath(r) {
		return false
	}

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

func isSafeRequestPath(r *http.Request) bool {
	raw := r.URL.RawPath
	if raw == "" {
		raw = r.URL.EscapedPath()
	}
	rawLower := strings.ToLower(raw)
	if strings.Contains(rawLower, "%2f") || strings.Contains(rawLower, "%5c") {
		return false
	}
	parts := strings.Split(r.URL.Path, "/")
	for _, part := range parts {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}
