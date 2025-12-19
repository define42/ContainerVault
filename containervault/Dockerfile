# ---------- build stage ----------
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Enable static binary
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

# Install node/npm for tsc
RUN apk add --no-cache nodejs npm

# Copy module files first (better caching)
COPY go.mod go.sum  ./
RUN go mod download

# Copy UI build files
COPY package.json ./
COPY ui ./ui
RUN npm install
RUN npm run build:ui

# Copy source
COPY *.go ./

# Build
RUN go build -o registry-proxy


# ---------- runtime stage ----------
FROM scratch

WORKDIR /app

# Copy binary
COPY --from=builder /app/registry-proxy /app/registry-proxy
COPY --from=builder /app/static /app/static

# TLS certs will be mounted
EXPOSE 8443


ENTRYPOINT ["/app/registry-proxy"]
