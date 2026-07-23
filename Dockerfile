FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /quicgate .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /quicgate /quicgate
ENV QG_DATA=/data
VOLUME /data
EXPOSE 80/tcp 443/tcp 443/udp 81/tcp
ENTRYPOINT ["/quicgate"]
