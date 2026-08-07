# Operations

Run one Relaybox process per data file. The default listen address is loopback (`127.0.0.1:8080`) and the default store is `data/relaybox.ndjson`. Never publish the service broadly without TLS, network controls, signature verification, and deliberate token handling.

## Secrets and forwarding

Prefer environment variables to command-line secret flags:

- `RELAYBOX_OPERATOR_TOKEN` sets the operator bearer token. Relaybox generates and logs one at startup when it is absent.
- `RELAYBOX_SECRET` sets the GitHub HMAC secret.
- `RELAYBOX_SENSITIVE_HEADERS` is a comma-separated extension to the default case-insensitive redaction policy.
- `RELAYBOX_FORWARD_AUTHORIZATION` injects a destination-only `Authorization` header during forwarding. It is not persisted with captures.

On startup, Relaybox scans the complete active append log for legacy request and response headers that match the current policy, replaces retained values, and compacts away historical values. Detail, SSE, replay, and forwarding paths also apply the policy when reading, so an interrupted migration fails closed at egress. Offline backups and copies made before a successful upgraded startup can still contain plaintext values. Treat those files as sensitive and rotate any credential that may have been recorded before upgrading.

The exact default names include `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `API-Key`, `X-API-Key`, `API-Token`, `X-API-Token`, `X-Auth-Token`, `X-Access-Token`, `X-Client-Token`, `X-Token`, `Secret-Key`, `X-Secret-Key`, `X-Secret`, `X-Client-Secret`, `X-Amz-Security-Token`, `X-Hub-Signature`, and `X-Hub-Signature-256`. Relaybox also normalizes case and punctuation to identify API-key, authentication, credential, cookie, signature, secret, and token names such as `X-ApiKey`, `Authentication`, and `X-Credential-ID`. Values are replaced with `[REDACTED]` before persistence and removed before forwarding.

When TLS terminates at a reverse proxy and the backend connection is plain HTTP, pass `-secure-cookie` so the browser session cookie retains its `Secure` attribute. Do not trust client-supplied forwarding headers to infer TLS state.

## Resource and retention settings

The most important bounds are:

- `-max-body` and `-max-inflight` bound request memory and concurrent reads.
- `-retention-captures` bounds retained captures (default 1,000).
- `-jobs-per-request` bounds retained original/replay jobs for one capture (default 8).
- `-retention-events` selects the mutation count that triggers log compaction (default 100,000 events).
- `-search-bytes` bounds the body prefix indexed per capture (default 64 KiB).
- `-attempts`, `-concurrency`, and `-queue-size` bound delivery attempts, workers, and wake-up hints.

Search query length is limited to 256 bytes, page size to 200, and work to the retained capture limit plus a two-second request budget. The API reports whether a scan was truncated. SSE catch-up and client buffers have independent event/byte limits.

When capture retention is full, Relaybox evicts the oldest capture whose jobs are all terminal. It never evicts pending, leased, or retrying work. If nothing is eligible, inbox requests receive `507 Insufficient Storage`; reduce unfinished work or raise retention deliberately. Replay similarly returns 507 when every retained job slot is active.

Compaction preserves the current request, attempt, and job state in a synced replacement file and advances the global sequence across the snapshot. The in-memory store keeps metadata, record offsets, and bounded search prefixes; full request and response bodies remain disk-backed and are read on demand. Stop Relaybox before copying or replacing the data file. Test recovery against a copy. A partial final event is removed on startup; earlier corruption, sequence gaps, invalid state, or digest mismatches require restoration from backup.

## Health, metrics, and shutdown

- `GET /healthz` verifies that the append store is not poisoned or closed.
- `GET /readyz` also verifies that the process is accepting work.
- `relaybox healthcheck` checks readiness for containers and supervisors.
- Authenticated `GET /api/metrics` returns bounded forwarding-job counts by state.
- SIGTERM stops acceptance, waits for durable work when possible, and cancels active requests at the process shutdown deadline.
- A write, sync, or compaction failure makes probes fail and rejects later writes. Restore writable durable storage and restart.

Queued/retrying work is discovered by polling; the in-memory channel is only a wake-up optimization. Startup immediately recovers leases owned by the previous process. At-least-once delivery means a destination can receive duplicates after crashes, so downstream systems should deduplicate Relaybox request/job IDs.

## Outbound and container operation

Outbound targets are fixed at startup. Public IPs are required by default, redirects and environment proxies are not used, and DNS is checked at dial time. Use `-allow-private-targets` only for a controlled development receiver; it disables private/loopback/link-local protections.

Container usage requires `RELAYBOX_OPERATOR_TOKEN`; set `RELAYBOX_SECRET` as well for authenticated GitHub deliveries. Compose binds the port to host loopback, uses a read-only root filesystem, drops capabilities, and enables `no-new-privileges`. The image runs as UID/GID 65532; ensure `/data` is writable by that identity.

CI builds the actual image, runs [`scripts/container-smoke.sh`](../scripts/container-smoke.sh), scans high/critical vulnerabilities, and preserves an image SBOM. The smoke test verifies non-root/read-only operation, readiness, capture/readback, forced-crash delivery recovery, CA roots, metrics, and graceful shutdown.
