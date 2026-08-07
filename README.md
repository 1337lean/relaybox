# Relaybox

[![CI](https://github.com/1337lean/relaybox/actions/workflows/ci.yml/badge.svg)](https://github.com/1337lean/relaybox/actions/workflows/ci.yml)
[![CodeQL](https://github.com/1337lean/relaybox/actions/workflows/codeql.yml/badge.svg)](https://github.com/1337lean/relaybox/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/1337lean/relaybox?display_name=tag)](https://github.com/1337lean/relaybox/releases)

Relaybox is a standard-library-only webhook inbox. It durably captures requests, verifies GitHub HMAC signatures, atomically suppresses duplicates, forwards through a fixed target with bounded retries, and exposes an authenticated browser inspector.

## Install

Requires Go 1.25.

After the first tagged release, install the CLI directly:

```sh
go install github.com/1337lean/relaybox/cmd/relaybox@latest
relaybox version
```

Until then, run the current source checkout with `go run ./cmd/relaybox` as shown below. Tagged releases provide checksummed Linux, macOS, and Windows archives for `amd64` and `arm64`, plus SBOMs and provenance attestations, and publish the container to `ghcr.io/1337lean/relaybox`. See [releasing](docs/releasing.md) for the verification and publication flow.

## Quick start

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

`serve` supports `-addr`, `-data`, `-secret`, `-operator-token`, `-forward`, `-allow-private-targets`, `-secure-cookie`, `-max-body`, `-max-inflight`, `-attempts`, `-concurrency`, `-queue-size`, `-retention-captures`, `-retention-events`, `-jobs-per-request`, and `-search-bytes`. Use `-secure-cookie` when TLS terminates at a reverse proxy. Size, concurrency, search, and retention settings have defensive upper bounds. `healthcheck` checks readiness; `demo` sends a sample event; `version` reports the build version.

- `POST /inbox[/anything]`: capture, intentionally usable without the operator token.
- `GET /api/requests?q=&offset=&limit=`: authenticated, bounded paginated search summaries (no bodies).
- `GET /api/requests/{id}`: authenticated detail.
- `POST /api/requests/{id}/replay`: authenticated replay to the configured target only.
- `GET /api/events`: authenticated SSE, with bounded `Last-Event-ID` resume support.
- `GET /api/metrics`: authenticated bounded forwarding-state counts.
- `GET /healthz`, `GET /readyz`: liveness and storage/readiness probes.

Bearer clients send `Authorization: Bearer TOKEN`. The UI exchanges the token for a domain-separated, derived session value in an HttpOnly, Strict SameSite operator cookie; state-changing cookie-authenticated requests require an exact same-origin `Origin` header.

## Durability and delivery

The append-only NDJSON log is synced for every event. Capture, deduplication, and the required forwarding intent are one durable record before `202 Accepted`; reuse of a delivery ID with a different body returns `409 Conflict`. Fixed workers lease and poll durable jobs, while the bounded in-memory channel is only a wake-up hint. Pending, retrying, expired, and prior-process leased jobs are recovered without depending on request re-enqueueing. Attempts and their resulting states are atomic. Delivery is at least once: a crash around an outbound request can repeat it.

Retention defaults to 1,000 captures and eight jobs per capture. Completed oldest data is evicted durably; unfinished forwarding is never evicted, and a full store returns `507 Insufficient Storage`. Search uses a bounded body-prefix index outside the store lock. SSE resumes from a bounded sequence ring rather than scanning the log.

Sensitive headers, including normalized API-key, authentication, credential, cookie, signature, secret, and token names, are redacted before persistence and removed from forwarding. Add organization-specific names with `RELAYBOX_SENSITIVE_HEADERS`. If a destination needs authentication, set `RELAYBOX_FORWARD_AUTHORIZATION`; it is injected at send time and is not stored with captures.

Redirects and outbound environment proxies are disabled. Targets must be configured by the operator; replay cannot supply a URL. Public destinations are allowed by default, while loopback, private, link-local, multicast, and unspecified addresses are blocked at dial time (including DNS results). Hop-by-hop headers and spoofable forwarding/Relaybox identity headers are removed before delivery. `-allow-private-targets` disables the IP protection and is for controlled development only.

## Container

```sh
RELAYBOX_OPERATOR_TOKEN='long-random-value' \
RELAYBOX_SECRET='github-webhook-secret' \
docker compose up --build
```

Compose passes secrets through the environment rather than command arguments, publishes only to host loopback, drops Linux capabilities, enables `no-new-privileges`, and makes the container root filesystem read-only. The scratch runtime includes CA roots for HTTPS forwarding and uses the real readiness command.

See [architecture](docs/architecture.md), [operations](docs/operations.md), [threat model](docs/threat-model.md), and [releasing](docs/releasing.md).

## Development

```sh
gofmt -w .
go vet ./...
go test -race ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.7.0 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
go run github.com/goreleaser/goreleaser/v2@v2.17.1 check
go build ./cmd/relaybox
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request and [SECURITY.md](SECURITY.md) for private vulnerability reporting.

## License

Relaybox is available under the [MIT License](LICENSE). Notices for code redistributed in binaries and container images are recorded in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and included in release artifacts.
