# Operations

Run one Relaybox process per data file. The default listen address is loopback (`127.0.0.1:8080`) and the default store is `data/relaybox.ndjson`. Prefer `RELAYBOX_OPERATOR_TOKEN` and `RELAYBOX_SECRET` over command-line secret flags, or capture the generated operator token from startup logs. Never publish the service broadly without TLS, network controls, signature verification, and deliberate token handling.

When TLS terminates at a reverse proxy and the backend connection is plain HTTP, pass `-secure-cookie` so the browser session cookie retains its `Secure` attribute. Do not trust client-supplied forwarding headers to infer TLS state.

- Liveness: `GET /healthz` verifies that the append store is not poisoned or closed.
- Readiness: `GET /readyz` additionally verifies that the process is accepting work.
- The `relaybox healthcheck` command checks readiness for container/supervisor probes.
- SIGTERM stops acceptance, gracefully shuts down HTTP, waits for queued/active work, and cancels request/backoff contexts at the configured process shutdown deadline.
- A store write/fsync failure makes probes fail and later writes are rejected. Restore writable durable storage and restart.
- Storage has no retention. Stop Relaybox before copying/replacing the NDJSON file. Test recovery against a copy.
- An incomplete final event is removed on startup. Records have a hard recovery-size bound and sequence numbers must remain contiguous. Earlier malformed data requires restoration from backup.

Outbound targets are fixed at startup. Public IPs are required by default, redirects and environment proxies are not used, and DNS is checked at dial time. Use `-allow-private-targets` only for a controlled development receiver; it disables private/loopback/link-local protections. At-least-once recovery means a destination can receive duplicates after crashes, so use the Relaybox IDs for downstream idempotency.

Container usage requires `RELAYBOX_OPERATOR_TOKEN`; set `RELAYBOX_SECRET` as well for authenticated GitHub deliveries. Compose binds the published port to host loopback, uses a read-only root filesystem, drops capabilities, and enables `no-new-privileges`. The image runs as UID/GID 65532; ensure `/data` is writable by that identity.
