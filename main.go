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

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
)


var proxyTransport http.RoundTripper = http.DefaultTransport

func cvRouter() http.Handler {
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

	router := chi.NewRouter()
	staticHandler := http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir)))
	router.Handle("/static/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/static/")
		if strings.HasSuffix(path, ".js") {
			w.Header().Set("Content-Type", "application/javascript")
		}
		setNoCacheHeaders(w)
		staticHandler.ServeHTTP(w, r)
	}))

	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
	router.Post("/login", handleLoginPost)
	router.Get("/login", handleLoginGet)
	router.HandleFunc("/logout", handleLogout)

	apiCfg := huma.DefaultConfig("ContainerVault", "1.0.0")
	apiCfg.OpenAPIPath = ""
	apiCfg.DocsPath = ""
	apiCfg.SchemasPath = ""
	api := humachi.New(router, apiCfg)
	registerAPI(api)

	router.NotFound(func(w http.ResponseWriter, r *http.Request) {
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
