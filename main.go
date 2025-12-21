package main

import (
	"fmt"
	"log"
	"mime"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

var proxyTransport http.RoundTripper = http.DefaultTransport

func cvRouter() *mux.Router {
	_ = mime.AddExtensionType(".js", "application/javascript")
	staticDir := resolveStaticDir()

	// Use single-host reverse proxy to forward traffic to the registry
	proxy := &httputil.ReverseProxy{
		Transport: proxyTransport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)
			pr.Out.Header.Del("Forwarded")
			pr.Out.Header.Del("X-Forwarded-For")
			pr.Out.Header.Del("X-Forwarded-Host")
			pr.Out.Header.Del("X-Forwarded-Proto")
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("Proxy-Authorization")
			pr.Out.Host = upstream.Host
			pr.SetXForwarded()
		},
	}

	proxy.FlushInterval = -1 // important for streaming blobs

	apiUnauthorized := func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}

	router := mux.NewRouter()
	staticHandler := http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir)))
	router.PathPrefix("/static/").Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/static/")
		if strings.HasSuffix(path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
		}
		setNoCacheHeaders(w)
		staticHandler.ServeHTTP(w, r)
	}))

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}).Methods(http.MethodGet)
	router.HandleFunc("/login", handleLogin)
	router.HandleFunc("/logout", handleLogout)
	api := router.PathPrefix("/api/").Subrouter()
	api.Use(requireSessionMiddleware(apiUnauthorized))
	api.HandleFunc("/dashboard", serveDashboard).Methods(http.MethodGet)
	api.HandleFunc("/catalog", handleCatalog)
	api.HandleFunc("/repos", handleRepos)
	api.HandleFunc("/tags", handleTags)
	api.HandleFunc("/taginfo", handleTagInfo)
	api.HandleFunc("/taglayers", handleTagLayers)

	router.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := authenticate(w, r)
		if !ok {
			// http.Error already sent
			return
		}

		if !authorize(user, r) {
			fmt.Println("forbidden", user.Name, r.Method, r.URL.Path, user)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		proxy.ServeHTTP(w, r)
	})
	return router
}

func main() {

	router := cvRouter()

	certPath := "/certs/registry.crt"
	keyPath := "/certs/registry.key"

	if err := ensureTLSCert(certPath, keyPath); err != nil {
		log.Fatalf("unable to ensure TLS certificate: %v", err)
	}

	log.Println("listening on :8443")
	server := &http.Server{
		Addr:              ":8443",
		Handler:           router,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(server.ListenAndServeTLS(certPath, keyPath))
}

func requireSessionMiddleware(onFail http.HandlerFunc) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := getSession(r); !ok {
				if onFail != nil {
					onFail(w, r)
					return
				}
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func resolveStaticDir() string {
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Join(filepath.Dir(exe), "static")
		if info, statErr := os.Stat(dir); statErr == nil && info.IsDir() {
			return dir
		}
	}
	return "./static"
}
