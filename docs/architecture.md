# Architecture

Relaybox is one Go process. `cmd/relaybox` owns configuration and bounded shutdown; `internal/app` owns HTTP, authorization, forwarding, retry policy, fixed workers, and SSE; `internal/store` owns the append-only event log and indexes; `internal/web` embeds the UI.

## Storage and work recovery

Every newline is a complete JSON event with a monotonic sequence. Appends are serialized, fully written, fsynced, indexed, then published. A write or sync failure poisons readiness and prevents later appends. Startup reconstructs requests, attempts, and delivery jobs, truncating only an incomplete final record. Sequence gaps, invalid event shapes, unknown event kinds, and request-body digest mismatches fail startup rather than silently rebuilding a misleading index.

Capture atomically checks and records idempotency. A delivery ID maps to one body hash; reuse with another body is a conflict. Without a delivery ID, the body SHA-256 is the fallback key.

A `forward.queued` event is durable before the inbox returns 202 or replay returns success. A fixed worker pool consumes a bounded queue. Jobs left queued or running are loaded on startup. This is at-least-once, not exactly-once: interruption after the destination receives a request but before completion is durable can cause a repeat. Destinations should honor `X-Relaybox-Job-ID` or `X-Relaybox-Request-ID` idempotently.

## Outbound and retries

Replay always uses the configured fixed target. URL parsing rejects credentials and non-HTTP schemes. Redirect following is disabled. The default dialer resolves the hostname and rejects loopback, private, link-local, multicast, and unspecified addresses; development can explicitly opt into private targets.

Only transport failures, 408, 425, 429, and 5xx retry. Valid `Retry-After`, including zero, takes precedence and is capped. Otherwise Relaybox uses capped exponential backoff with deterministic job/attempt jitter. Attempts and terminal states are durable, including fatal and poison outcomes.

## SSE

Subscription registration and a snapshot of the already-opened store file happen under the store lock, eliminating both the snapshot/live gap and path-replacement races. Events have named types and monotonic IDs. A new stream starts at the current sequence; clients resume with standard `Last-Event-ID` (or the compatibility cursor query). Catch-up is capped at 1,000 events and 32 MiB, with `409 Conflict` returned for an older cursor. Slow subscribers are disconnected on buffer overflow and can reconnect from their last ID; the bundled UI reloads the authoritative request list before restarting a failed stream.
