# The build image is pinned by digest and matches the toolchain directive in
# go.mod, so a release is built with exactly the Go patch level CI tested and
# scanned. Dependabot proposes digest updates.
FROM golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS build
ARG VERSION=dev
# Never let the go command switch to a different toolchain inside the build.
ENV GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /quicgate .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /quicgate /quicgate
ENV QG_DATA=/data
VOLUME /data
EXPOSE 80/tcp 443/tcp 443/udp 81/tcp
ENTRYPOINT ["/quicgate"]
