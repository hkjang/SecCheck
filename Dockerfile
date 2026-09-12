# syntax=docker/dockerfile:1.7
FROM node:22-bookworm-slim AS web-build
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.26.6-bookworm AS go-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/seccheck ./cmd/seccheck

FROM debian:bookworm-slim
ARG VERSION=dev
LABEL org.opencontainers.image.title="SecCheck" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.source="https://github.com/hkjang/SecCheck" \
      org.opencontainers.image.description="Offline-capable security review checklist platform"
# upgrade, not just install. The base image carries whatever Debian had built
# into it on the day it was tagged, and the vulnerability gate rejects anything
# fixable — libpcre2-8-0 shipped at 10.42-1 with two HIGH holes already patched
# in 10.42-1+deb12u1. Installing only the packages named below leaves the rest at
# the version the tag froze, and the build fails on a hole that apt can close.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends ca-certificates tzdata fonts-nanum \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 seccheck \
    && useradd --system --uid 10001 --gid seccheck --home-dir /app --shell /usr/sbin/nologin seccheck
WORKDIR /app
COPY --from=go-build /out/seccheck /app/seccheck
COPY --from=web-build /src/web/dist /app/web/dist
RUN mkdir -p /app/data && chown -R seccheck:seccheck /app
USER 10001:10001
EXPOSE 8080
VOLUME ["/app/data"]
ENTRYPOINT ["/app/seccheck"]
