FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ARG VERSION=dev
RUN apk add --no-cache ca-certificates \
	&& CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=${VERSION}" -o /relaybox ./cmd/relaybox \
	&& CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w' -o /relaybox-receiver ./examples/receiver \
    && mkdir /data \
    && chown 65532:65532 /data

FROM scratch AS receiver
COPY --from=build /relaybox-receiver /relaybox-receiver
COPY --from=build /src/LICENSE /LICENSE
COPY --from=build /src/THIRD_PARTY_NOTICES.md /THIRD_PARTY_NOTICES.md
USER 65532:65532
ENTRYPOINT ["/relaybox-receiver"]

FROM scratch AS runtime
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.source="https://github.com/1337lean/relaybox" \
	org.opencontainers.image.description="A local-first webhook inbox and forwarding engine" \
	org.opencontainers.image.licenses="MIT" \
	org.opencontainers.image.version="${VERSION}" \
	org.opencontainers.image.revision="${REVISION}"
COPY --from=build /relaybox /relaybox
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /src/LICENSE /LICENSE
COPY --from=build /src/THIRD_PARTY_NOTICES.md /THIRD_PARTY_NOTICES.md
COPY --from=build --chown=65532:65532 /data /data
USER 65532:65532
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/relaybox"]
CMD ["serve", "-addr", ":8080", "-data", "/data/relaybox.ndjson"]
