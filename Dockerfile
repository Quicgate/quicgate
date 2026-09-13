# The build image is pinned by digest and matches the toolchain directive in
# go.mod, so a release is built with exactly the Go patch level CI tested and
# scanned. Dependabot proposes digest updates.
FROM golang:1.26.8-alpine@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS build
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
