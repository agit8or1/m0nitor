# Caddy v2.11.7 rebuilt from source with a patched Go toolchain and dependency versions, plus Alpine package updates,
# until upstream publishes a rebuilt image. Same module set as the official image (no plugins).
# Refresh: docker compose build --pull caddy && docker compose up -d caddy
# When upstream releases a fixed image, switch docker-compose.yml back to it and delete this directory.
FROM golang:1.26.10-alpine AS build
RUN apk add --no-cache git && go install github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.7
RUN xcaddy build v2.11.7 --output /caddy \
      --replace github.com/go-jose/go-jose/v4=github.com/go-jose/go-jose/v4@v4.1.6 \
      --replace golang.org/x/net=golang.org/x/net@v0.60.0

FROM caddy:2.11.7-alpine
RUN apk upgrade --no-cache
COPY --from=build /caddy /usr/bin/caddy
