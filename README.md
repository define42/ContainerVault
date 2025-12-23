# ContainerVault

ContainerVault is a Go-based private registry proxy with LDAP authentication and a web dashboard for browsing namespaces, repositories, tags, and image details.

## Codecov
[![codecov](https://codecov.io/github/define42/ContainerVault/graph/badge.svg?token=CFBGGOI5OM)](https://codecov.io/github/define42/ContainerVault-Enterprise)

## Features
- LDAP login with namespace-scoped access control.
- Registry proxying with TLS.
- Web dashboard for tags, digests, layers, and history.
- Docker Compose setup for local testing.

## Requirements
- Docker + Docker Compose
- Node.js (for building the UI when working locally)

## Quick start
1) Start the stack:
```
make all
```
2) Open the UI:
```
https://localhost/login
```

## Configuration
Set these environment variables for the proxy service:
- `REGISTRY_UPSTREAM` (default: `http://registry:5000`)
- `LDAP_URL` (default: `ldaps://ldap:389`)
- `LDAP_BASE_DN` (default: `dc=glauth,dc=com`)
- `LDAP_USER_FILTER` (default: `(uid=%s)`)
- `LDAP_GROUP_ATTRIBUTE` (default: `memberOf`)
- `LDAP_GROUP_PREFIX` (default: `team`)
- `LDAP_USER_DOMAIN` (default: `@example.com`)
- `LDAP_STARTTLS` (default: `false`)
- `LDAP_SKIP_TLS_VERIFY` (default: `false`)

## UI build
If you edit `/home/define42/git/docker/ui/ui.ts`, rebuild the static assets:
```
npm --prefix /home/define42/git/docker run build:ui
```

## Tests
Run unit and integration tests:
```
go test ./...
```
