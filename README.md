# ContainerVault

ContainerVault is a Go-based forward proxy layered on top of the official self-hosted Docker Registry, enhancing it with LDAP-based authentication and a web UI for navigating namespaces, repositories, tags, and detailed image information.

[![codecov](https://codecov.io/github/define42/container-vault/graph/badge.svg?token=CFBGGOI5OM)](https://codecov.io/github/define42/container-vault)
[![Go Report Card](https://goreportcard.com/badge/github.com/define42/container-vault)](https://goreportcard.com/report/github.com/define42/container-vault)

## Features
- LDAP login with namespace-scoped access control.
- Docker registry proxy (TLS-terminated) with push/pull/delete enforcement.
- Web UI for repositories, tags, digests, layers, and history (includes tag delete and refresh).
- Huma v2 API under `/api` for the UI.
- Docker Compose stack for local testing.

## Quick start
1) Build and start the stack:
```
docker compose up -d --build
```
2) Open the UI (self-signed cert):
```
https://localhost/login
```

## Docker Compose example
Minimal compose file (registry + ContainerVault):
```
version: "3.8"

services:
  registry:
    image: registry:2
    container_name: registry
    restart: always
    volumes:
      - ./data:/var/lib/registry
    environment:
      REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY: /var/lib/registry
      REGISTRY_HTTP_ADDR: :5000
      REGISTRY_STORAGE_DELETE_ENABLED: true

  container-vault:
    build: ./
    container_name: container-vault
    restart: always
    ports:
      - "443:8443"
    depends_on:
      - registry
    environment:
      REGISTRY_UPSTREAM: http://registry:5000
```

LDAP configuration example (add to the ContainerVault service):
```
    environment:
      REGISTRY_UPSTREAM: http://registry:5000
      LDAP_URL: ldaps://ldap:389
      LDAP_BASE_DN: dc=glauth,dc=com
      LDAP_USER_FILTER: (mail=%s)
      LDAP_GROUP_ATTRIBUTE: memberOf
      LDAP_GROUP_PREFIX: team
      LDAP_USER_DOMAIN: "@example.com"
      LDAP_STARTTLS: "false"
      LDAP_SKIP_TLS_VERIFY: "true"
```

## Permission model
Group names must end in one of the supported suffixes; groups without a suffix are ignored.
- `_r`: read/pull only
- `_rw`: read + write (push)
- `_rd`: read + delete
- `_rwd`: read + write + delete

Group names are derived from LDAP DNs (e.g. `cn=team1_rw,ou=groups,...` -> `team1_rw`). The `LDAP_GROUP_PREFIX` filter is applied before suffix parsing.
Namespaces are mapped by stripping the permission suffix from the group name (e.g. `team1_rwd` -> namespace `team1`); only groups that start with the configured prefix and end with a supported suffix are considered.
Example: group `team1_rwd` maps to namespace `team1`, so a push looks like `docker push localhost/team1/alpine:test`.

## API
All API endpoints are under `/api` and require a session cookie (`cv_session`), issued after login.
- `GET /api/dashboard`
- `GET /api/catalog?namespace=<ns>`
- `GET /api/repos?namespace=<ns>`
- `GET /api/tags?repo=<ns>/<repo>`
- `GET /api/taginfo?repo=<ns>/<repo>&tag=<tag>`
- `GET /api/taglayers?repo=<ns>/<repo>&tag=<tag>`
- `DELETE /api/tag?repo=<ns>/<repo>&tag=<tag>`

OpenAPI/Docs endpoints are disabled by default in `main.go` (paths set to empty). To enable, set `apiCfg.OpenAPIPath`, `apiCfg.DocsPath`, and `apiCfg.SchemasPath`.

## Registry proxy
Registry requests go through `/v2/*` and require HTTP Basic Auth. Access is restricted to namespaces derived from the authenticated LDAP groups and permission suffixes.

## Configuration
LDAP settings are loaded from environment variables:
- `LDAP_URL` (default: `ldaps://ldap:389`)
- `LDAP_BASE_DN` (default: `dc=glauth,dc=com`)
- `LDAP_USER_FILTER` (default: `(mail=%s)`)
- `LDAP_GROUP_ATTRIBUTE` (default: `memberOf`)
- `LDAP_GROUP_PREFIX` (default: `team`)
- `LDAP_USER_DOMAIN` (default: `@example.com`)
- `LDAP_STARTTLS` (default: `false`)
- `LDAP_SKIP_TLS_VERIFY` (default: `true`)

TLS with Certmagic (optional):
- `CERTMAGIC_ENABLE` (default: `false`)
- `CERTMAGIC_DOMAINS` (comma-separated, required when enabled)
- `CERTMAGIC_EMAIL` (optional ACME account email)
- `CERTMAGIC_CA` (custom ACME directory URL)
- `CERTMAGIC_CA_ROOT` (path to a PEM CA root cert for the ACME server)
- `CERTMAGIC_STORAGE` (path for cert storage; defaults to certmagic's standard location)
- `CERTMAGIC_HTTP_PORT` (alternate HTTP-01 port if your ACME server supports it)
- `CERTMAGIC_TLS_ALPN_PORT` (alternate TLS-ALPN port if your ACME server supports it)

When Certmagic is enabled, ContainerVault uses ACME with TLS-ALPN challenge by default and serves with the managed certificate.

The registry upstream URL is currently configured in `config.go` (default: `http://registry:5000`, matching `docker-compose.yml`).

## Test with glauth/glauth LdapServer

Test LDAP users in `testldap/default-config.cfg`:
- `hackers` / `dogood`
- `johndoe` / `dogood`
- `serviceuser` / `mysecret`

Minimal compose file (ldap):
```
  ldap:
    image: glauth/glauth
    container_name: ldap
    restart: always
    ports:
      - "389:389"
    volumes:
      - ./testldap/default-config.cfg:/app/config/config.cfg
      - ./testldap/key.pem:/app/config/key.pem
      - ./testldap/cert.pem:/app/config/cert.pem
```

## UI build
If you edit `ui/ui.ts`, rebuild the static assets:
```
npm --prefix ui run build:ui
```
The build outputs to `static/`.

## Tests
Run unit and integration tests:
```
go test ./...
```
Integration tests use Docker/testcontainers, and the proxy push/pull test relies on the Docker CLI.

## License
Unlicense. See `LICENSE`.
