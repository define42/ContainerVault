package main

import (
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"sort"
	"strings"
)

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

func handleLoginPost(w http.ResponseWriter, r *http.Request) {
	username, password, ok, err := extractCredentials(r)
	if err != nil {
		serveLogin(w, "Invalid form submission.")
		return
	}
	if !ok {
		serveLogin(w, "Missing credentials.")
		return
	}

	user, access, err := ldapAuthenticateAccess(username, password)
	if err != nil {
		log.Printf("ldap auth failed for %s: %v", username, err)
		serveLogin(w, "Invalid credentials.")
		return
	}

	token := createSession(user, access)
	http.SetCookie(w, &http.Cookie{
		Name:     "cv_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/api/dashboard", http.StatusSeeOther)
}

func handleLoginGet(w http.ResponseWriter, r *http.Request) {
	serveLogin(w, "")
}

func serveLogin(w http.ResponseWriter, message string) {
	setNoCacheHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	errorHTML := ""
	if message != "" {
		errorHTML = `<div class="error">` + html.EscapeString(message) + `</div>`
	}
	fmt.Fprint(w, strings.Replace(loginHTML, "{{ERROR}}", errorHTML, 1))
}

func renderDashboardHTML(sess sessionData) ([]byte, error) {
	permissions := buildNamespacePermissions(sess.Namespaces, sess.Access)
	bootstrapJSON, err := json.Marshal(map[string]any{
		"namespaces":  sess.Namespaces,
		"permissions": permissions,
	})
	if err != nil {
		return nil, err
	}

	page := strings.Replace(dashboardHTML, "{{USERNAME}}", html.EscapeString(sess.User.Name), 1)
	page = strings.Replace(page, "{{BOOTSTRAP}}", string(bootstrapJSON), 1)
	return []byte(page), nil
}

type namespacePermission struct {
	Namespace     string   `json:"namespace"`
	PullOnly      bool     `json:"pull_only"`
	DeleteAllowed bool     `json:"delete_allowed"`
	Groups        []string `json:"groups,omitempty"`
}

func hasPermissionSuffix(group string) bool {
	switch {
	case strings.HasSuffix(group, "_rwd"):
		return true
	case strings.HasSuffix(group, "_rw"):
		return true
	case strings.HasSuffix(group, "_rd"):
		return true
	case strings.HasSuffix(group, "_r"):
		return true
	default:
		return false
	}
}

func buildNamespacePermissions(namespaces []string, access []Access) []namespacePermission {
	perms := make(map[string]*namespacePermission, len(namespaces))
	groupSets := make(map[string]map[string]struct{}, len(namespaces))
	seen := make(map[string]bool, len(namespaces))

	for _, entry := range access {
		if entry.Namespace == "" {
			continue
		}
		seen[entry.Namespace] = true
		perm := perms[entry.Namespace]
		if perm == nil {
			perm = &namespacePermission{
				Namespace: entry.Namespace,
				PullOnly:  true,
			}
			perms[entry.Namespace] = perm
		}
		if !entry.PullOnly {
			perm.PullOnly = false
		}
		if entry.DeleteAllowed {
			perm.DeleteAllowed = true
		}
		if entry.Group != "" && hasPermissionSuffix(entry.Group) {
			set := groupSets[entry.Namespace]
			if set == nil {
				set = map[string]struct{}{}
				groupSets[entry.Namespace] = set
			}
			set[entry.Group] = struct{}{}
		}
	}

	for ns, perm := range perms {
		set := groupSets[ns]
		if len(set) == 0 {
			continue
		}
		perm.Groups = make([]string, 0, len(set))
		for group := range set {
			perm.Groups = append(perm.Groups, group)
		}
		sort.Strings(perm.Groups)
	}

	result := make([]namespacePermission, 0, len(namespaces))
	for _, ns := range namespaces {
		if ns == "" {
			continue
		}
		if perm, ok := perms[ns]; ok {
			result = append(result, *perm)
			continue
		}
		if seen[ns] {
			continue
		}
		result = append(result, namespacePermission{
			Namespace:     ns,
			PullOnly:      false,
			DeleteAllowed: false,
		})
	}

	return result
}

const (
	cacheControlValue = "no-store, no-cache, must-revalidate, max-age=0"
	pragmaValue       = "no-cache"
	expiresValue      = "0"
)

func setNoCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", cacheControlValue)
	w.Header().Set("Pragma", pragmaValue)
	w.Header().Set("Expires", expiresValue)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
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
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func namespaceAllowed(allowed []string, namespace string) bool {
	for _, ns := range allowed {
		if ns == namespace {
			return true
		}
	}
	return false
}
