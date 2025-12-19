package main

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"strings"
)

func serveLanding(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, landingHTML)
}

func extractCredentials(r *http.Request) (string, string, bool, error) {
	username, password, ok := r.BasicAuth()
	if ok && username != "" && password != "" {
		return username, password, true, nil
	}
	if err := r.ParseForm(); err != nil {
		return "", "", false, err
	}
	username = strings.TrimSpace(r.FormValue("username"))
	password = r.FormValue("password")
	if username == "" || password == "" {
		return username, password, false, nil
	}
	return username, password, true, nil
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, loginHTML)
		return
	case http.MethodPost:
		username, password, ok, err := extractCredentials(r)
		if err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		if !ok {
			http.Error(w, "missing credentials", http.StatusBadRequest)
			return
		}

		user, access, err := ldapAuthenticateAccess(username, password)
		if err != nil {
			log.Printf("ldap auth failed for %s: %v", username, err)
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		token := createSession(user, access)
		http.SetCookie(w, &http.Cookie{
			Name:     "cv_session",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func serveDashboard(w http.ResponseWriter, r *http.Request) {
	sess, ok := getSession(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	bootstrapJSON, err := json.Marshal(map[string]any{
		"namespaces": sess.Namespaces,
	})
	if err != nil {
		http.Error(w, "unable to render dashboard", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, dashboardHTML, html.EscapeString(sess.User.Name), string(bootstrapJSON))
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie("cv_session")
	if err == nil && cookie.Value != "" {
		sessionMu.Lock()
		delete(sessions, cookie.Value)
		sessionMu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "cv_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func handleCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sess, ok := getSession(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	namespace := strings.TrimSpace(r.URL.Query().Get("namespace"))
	if namespace == "" || !namespaceAllowed(sess.Namespaces, namespace) {
		http.Error(w, "namespace not allowed", http.StatusForbidden)
		return
	}

	repos, err := fetchCatalog(r.Context(), namespace)
	if err != nil {
		http.Error(w, "registry unavailable", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"username":     sess.User.Name,
		"namespace":    namespace,
		"repositories": repos,
	})
}

func namespaceAllowed(allowed []string, namespace string) bool {
	for _, ns := range allowed {
		if ns == namespace {
			return true
		}
	}
	return false
}

func handleRepos(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sess, ok := getSession(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	namespace := strings.TrimSpace(r.URL.Query().Get("namespace"))
	if namespace == "" || !namespaceAllowed(sess.Namespaces, namespace) {
		http.Error(w, "namespace not allowed", http.StatusForbidden)
		return
	}

	repos, err := fetchRepos(r.Context(), namespace)
	if err != nil {
		http.Error(w, "registry unavailable", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"namespace":    namespace,
		"repositories": repos,
	})
}

func handleTags(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sess, ok := getSession(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	repo := strings.TrimSpace(r.URL.Query().Get("repo"))
	if repo == "" {
		http.Error(w, "missing repo", http.StatusBadRequest)
		return
	}

	parts := strings.SplitN(repo, "/", 2)
	if len(parts) < 2 {
		http.Error(w, "invalid repo", http.StatusBadRequest)
		return
	}
	namespace := parts[0]
	if !namespaceAllowed(sess.Namespaces, namespace) {
		http.Error(w, "namespace not allowed", http.StatusForbidden)
		return
	}

	tags, err := fetchTags(r.Context(), repo)
	if err != nil {
		http.Error(w, "registry unavailable", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"repo": repo,
		"tags": tags,
	})
}

func handleTagInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sess, ok := getSession(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	repo := strings.TrimSpace(r.URL.Query().Get("repo"))
	tag := strings.TrimSpace(r.URL.Query().Get("tag"))
	if repo == "" || tag == "" {
		http.Error(w, "missing repo or tag", http.StatusBadRequest)
		return
	}

	parts := strings.SplitN(repo, "/", 2)
	if len(parts) < 2 {
		http.Error(w, "invalid repo", http.StatusBadRequest)
		return
	}
	namespace := parts[0]
	if !namespaceAllowed(sess.Namespaces, namespace) {
		http.Error(w, "namespace not allowed", http.StatusForbidden)
		return
	}

	info, err := fetchTagInfo(r.Context(), repo, tag)
	if err != nil {
		http.Error(w, "registry unavailable", http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(info)
}
