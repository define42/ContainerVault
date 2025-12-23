package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthorizeNamespaceAndPing(t *testing.T) {
	user := &User{Namespace: "team1"}

	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	if !authorize(user, req) {
		t.Fatalf("expected /v2/ ping to be allowed")
	}

	req = httptest.NewRequest(http.MethodGet, "/v2/team1/repo", nil)
	if !authorize(user, req) {
		t.Fatalf("expected namespace request to be allowed")
	}

	req = httptest.NewRequest(http.MethodGet, "/v2/team2/repo", nil)
	if authorize(user, req) {
		t.Fatalf("expected other namespace to be denied")
	}
}

func TestAuthorizePullOnly(t *testing.T) {
	user := &User{Namespace: "team1", PullOnly: true}

	req := httptest.NewRequest(http.MethodGet, "/v2/team1/repo", nil)
	if !authorize(user, req) {
		t.Fatalf("expected GET to be allowed for pull-only")
	}

	req = httptest.NewRequest(http.MethodPost, "/v2/team1/repo", nil)
	if authorize(user, req) {
		t.Fatalf("expected POST to be denied for pull-only")
	}
}

func TestAuthorizePullOnlyWithDelete(t *testing.T) {
	user := &User{Namespace: "team1", PullOnly: true, DeleteAllowed: true}

	req := httptest.NewRequest(http.MethodDelete, "/v2/team1/repo", nil)
	if !authorize(user, req) {
		t.Fatalf("expected DELETE to be allowed for pull-only delete")
	}

	req = httptest.NewRequest(http.MethodPost, "/v2/team1/repo", nil)
	if authorize(user, req) {
		t.Fatalf("expected POST to be denied for pull-only delete")
	}
}

func TestAuthorizeDelete(t *testing.T) {
	user := &User{Namespace: "team1", DeleteAllowed: false}
	req := httptest.NewRequest(http.MethodDelete, "/v2/team1/repo", nil)
	if authorize(user, req) {
		t.Fatalf("expected delete to be denied when not allowed")
	}
}

func TestAuthorizeRejectsDotSegments(t *testing.T) {
	user := &User{Namespace: "team1"}
	req := httptest.NewRequest(http.MethodGet, "/v2/team1/../team2/repo", nil)
	if authorize(user, req) {
		t.Fatalf("expected dot-segment path to be denied")
	}
}

func TestAuthorizeRejectsEncodedSlash(t *testing.T) {
	user := &User{Namespace: "team1"}
	req := httptest.NewRequest(http.MethodGet, "/v2/team1/repo/manifests/latest", nil)
	req.URL.RawPath = "/v2/team1%2frepo/manifests/latest"
	if authorize(user, req) {
		t.Fatalf("expected encoded slash path to be denied")
	}
}
