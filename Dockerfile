# The build image is pinned by digest and matches the toolchain directive in
# go.mod, so a release is built with exactly the Go patch level CI tested and
# scanned. Dependabot proposes digest updates.
#
# The build stage runs on the builder's own platform and cross-compiles for the
# target one (Go needs no emulator for that, and the binary has no cgo), so the
# arm64 image costs a second compile instead of a compile under QEMU.
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
ARG VERSION=dev
# Never let the go command switch to a different toolchain inside the build.
ENV GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /quicgate .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /quicgate /quicgate
ENV QG_DATA=/data
VOLUME /data
EXPOSE 80/tcp 443/tcp 443/udp 81/tcp
ENTRYPOINT ["/quicgate"]
