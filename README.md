# Relaybox

Relaybox is a standard-library-only webhook inbox. It durably captures requests, verifies GitHub HMAC signatures, atomically suppresses duplicates, forwards through a fixed target with bounded retries, and exposes an authenticated browser inspector.

## Quick start

Requires Go 1.25.

```sh
RELAYBOX_OPERATOR_TOKEN='replace-with-a-long-random-value' \
  go run ./cmd/relaybox serve
# Open http://127.0.0.1:8080 and enter that token.
curl -X POST http://127.0.0.1:8080/inbox -H 'Content-Type: application/json' -d '{"hello":"world"}'
```

`RELAYBOX_OPERATOR_TOKEN` and `RELAYBOX_SECRET` avoid exposing secrets in process arguments; the equivalent flags remain available. If the operator token is omitted, Relaybox generates one and prints it once at startup. The inbox and health probes remain unauthenticated; the list, detail, replay, SSE, and session endpoints require the operator token. Relaybox binds `127.0.0.1:8080` by default and warns when signature verification is disabled.

Local forwarding requires an explicit development opt-in because loopback/private targets are blocked by default:

```sh
go run ./examples/receiver -addr :9090
go run ./cmd/relaybox serve -operator-token dev-token -forward http://127.0.0.1:9090/hooks -allow-private-targets
```

## Commands and API

`serve` supports `-addr`, `-data`, `-secret`, `-operator-token`, `-forward`, `-allow-private-targets`, `-secure-cookie`, `-max-body`, `-max-inflight`, `-attempts`, `-concurrency`, and `-queue-size`. Use `-secure-cookie` when TLS terminates at a reverse proxy. Size and concurrency settings have defensive upper bounds. `healthcheck` checks readiness; `demo` sends a sample event; `version` reports the build version.

- `POST /inbox[/anything]`: capture, intentionally usable without the operator token.
- `GET /api/requests?q=&offset=&limit=`: authenticated paginated summaries (no bodies).
- `GET /api/requests/{id}`: authenticated detail.
- `POST /api/requests/{id}/replay`: authenticated replay to the configured target only.
- `GET /api/events`: authenticated SSE, with bounded `Last-Event-ID` resume support.
- `GET /healthz`, `GET /readyz`: liveness and storage/readiness probes.

Bearer clients send `Authorization: Bearer TOKEN`. The UI exchanges the token for a domain-separated, derived session value in an HttpOnly, Strict SameSite operator cookie; state-changing cookie-authenticated requests require an exact same-origin `Origin` header.

## Durability and delivery

The append-only NDJSON log is fsynced for every event. Capture and delivery-ID deduplication occur under one store lock; reuse of a delivery ID with a different body returns `409 Conflict`. Forward intent is persisted before `202 Accepted`. Fixed workers consume a bounded queue, and queued/running jobs are resumed after restart. Delivery is at least once: a crash around an outbound request can repeat it. Attempts and terminal failure/poison states are persisted.

Redirects and outbound environment proxies are disabled. Targets must be configured by the operator; replay cannot supply a URL. Public destinations are allowed by default, while loopback, private, link-local, multicast, and unspecified addresses are blocked at dial time (including DNS results). Hop-by-hop headers and spoofable forwarding/Relaybox identity headers are removed before delivery. `-allow-private-targets` disables the IP protection and is for controlled development only.

## Container

```sh
RELAYBOX_OPERATOR_TOKEN='long-random-value' \
RELAYBOX_SECRET='github-webhook-secret' \
docker compose up --build
```

Compose passes secrets through the environment rather than command arguments, publishes only to host loopback, drops Linux capabilities, enables `no-new-privileges`, and makes the container root filesystem read-only. The scratch runtime includes CA roots for HTTPS forwarding and uses the real readiness command.

See [architecture](docs/architecture.md), [operations](docs/operations.md), and [threat model](docs/threat-model.md).

## Development

```sh
gofmt -w .
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/relaybox
```
