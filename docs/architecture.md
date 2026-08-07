# Architecture

Relaybox is one Go process. `cmd/relaybox` owns configuration and bounded shutdown; `internal/app` owns HTTP, authorization, forwarding, retry policy, fixed workers, and SSE; `internal/store` owns the append-only event log, retention, compaction, and indexes; and `internal/web` embeds the UI.

## Storage and acknowledgement

Every newline is one complete JSON event with a monotonic sequence. Appends are serialized, fully written, synced, indexed, and then published to live subscribers. A write or sync failure poisons readiness and prevents later appends. Startup truncates only an incomplete final record and rejects malformed JSON, sequence gaps, unknown event kinds, invalid event shapes, and request-body digest mismatches.

When forwarding is configured, `capture.accepted` contains both the request and its initial `pending` forwarding job. Deduplication is checked and that combined event is written and synced under one store lock. Relaybox returns `202 Accepted` only after this single durable commit. When forwarding is disabled, the same event contains only the request. A duplicate returns the existing request and leaves its original job discoverable; it never creates a second initial intent.

The in-memory worker channel is only a bounded wake-up hint. Losing a hint cannot lose work because workers poll durable state. If retention is full and every candidate capture has unfinished forwarding work, the store rejects a new capture instead of evicting required work.

## Forwarding state machine

The durable states are:

```text
pending ──claim──> leased ──success────────────> succeeded
   ▲                  │
   │                  ├─retryable failure─────> retrying ──due──> leased
   │                  ├─non-retryable failure─> fatal
   │                  ├─attempts exhausted────> dead-letter
   │                  └─invalid durable data──> poison
   └──── process-start recovery of stale leases
```

A claim records a unique in-process owner and lease expiry. Only that owner may record the attempt and resulting transition. The attempt and its `retrying`, `succeeded`, `fatal`, or `dead-letter` state are one synced event, so neither half can be persisted alone. Startup makes leases from the previous process immediately claimable; normal polling also reclaims expired leases. Job IDs remain stable across retries and are sent as `X-Relaybox-Job-ID`.

Delivery is at least once. Interruption after the destination processes a request but before Relaybox records success can repeat the request. Destinations should handle `X-Relaybox-Job-ID` or `X-Relaybox-Request-ID` idempotently. Retryable outcomes are transport failures, HTTP 408, 425, 429, and 5xx. Valid `Retry-After` values take precedence over capped exponential backoff with deterministic jitter. Non-retryable responses become `fatal`; exhausted retries become `dead-letter`.

## Redaction and outbound headers

Relaybox applies a case-insensitive sensitive-header policy before persistence. The defaults cover authorization, proxy authorization, cookies, common API key/token/secret names, AWS security tokens, and GitHub signature headers. `RELAYBOX_SENSITIVE_HEADERS` adds organization-specific names. Persisted records, APIs, SSE, search, metrics, logs, and ordinary forwarding therefore never receive the original values.

Forwarding removes every redacted and hop-by-hop header. If the destination needs authentication, `RELAYBOX_FORWARD_AUTHORIZATION` injects a separate `Authorization` value at send time; that value is never stored as capture data.

## Search, SSE, and retention

Each capture has a normalized search index containing identifiers, path, and at most `-search-bytes` body bytes. A list request copies bounded summaries and index references under `RLock`, then matches, sorts, and paginates outside the lock with request cancellation and a two-second handler budget. Responses include `truncated` if the configured scan limit prevented a complete scan.

SSE catch-up reads an in-memory sequence ring instead of scanning the event log. The ring defaults to 1,000 events and 32 MiB. A cursor older than the ring receives `409 Conflict`; live subscribers have a bounded buffer and are disconnected on overflow. Network writes have deadlines, and clients reconnect from their last delivered sequence.

The default policy retains 1,000 captures, eight jobs per capture, ten attempts per job, and a 64 KiB body-search prefix. Completed oldest data is evicted by identifiers recorded in the next durable event. Unfinished work is never selected for eviction. When the event-count threshold is crossed, the store writes retained state to a synced temporary file, atomically replaces the log, syncs the directory, and continues the global sequence. Recovery accepts a compacted log whose first retained sequence is greater than one.

## Outbound network boundary

Replay always uses the configured fixed target. URL parsing rejects credentials and non-HTTP schemes. Redirect following and environment proxy inheritance are disabled. The default dialer resolves the hostname at connection time and rejects loopback, private, link-local, multicast, unspecified, translation, transition, documentation, benchmarking, and shared-address destinations. Development can explicitly opt into private targets.
