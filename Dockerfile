FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN apk add --no-cache ca-certificates \
    && CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w' -o /relaybox ./cmd/relaybox \
    && mkdir /data \
    && chown 65532:65532 /data

FROM scratch
COPY --from=build /relaybox /relaybox
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /data /data
USER 65532:65532
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/relaybox"]
CMD ["serve", "-addr", ":8080", "-data", "/data/relaybox.ndjson"]
