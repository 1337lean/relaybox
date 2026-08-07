# Threat Model

Relaybox accepts attacker-controlled inbox bodies and headers. Controls include bounded body size and concurrent reads, bounded response capture, header and HTTP timeouts, constant-time HMAC verification when configured, pre-persistence sensitive-header redaction, atomic capture/intent persistence, fixed workers with durable leases, capped retries, lifecycle cancellation, enforced retention, and restrictive browser headers. The browser UI uses external assets under a CSP that disallows inline script and style.

## Administrative and browser boundary

The list, detail, replay, SSE, metrics, and session endpoints require an operator token. The UI exchanges a bearer token for a domain-separated derived session value in an HttpOnly Strict SameSite cookie. State-changing cookie-authenticated requests require an Origin, and every supplied Origin must match both the request host and expected HTTP/HTTPS scheme. `-secure-cookie` establishes HTTPS as the expected external scheme behind a TLS-terminating proxy.

The inbox and health probes remain unauthenticated so webhook senders and infrastructure can reach them. Configure `RELAYBOX_SECRET` to authenticate GitHub-style deliveries. Health probes expose status only; job metrics require operator authentication.

## Secret boundary

Inbound sensitive headers and configured organization-specific names are replaced before any durable or presentation path. Redacted values are removed from outbound requests. Destination authentication comes from the separate `RELAYBOX_FORWARD_AUTHORIZATION` environment value and is injected only while constructing the outbound request. Metrics use fixed state labels, and errors/logs do not include header values.

Relaybox does not encrypt stored bodies. A payload body can itself contain secrets, and an operator can read and replay retained payloads. Protect the store, process environment, and startup logs. Redaction protects named headers; it is not content inspection or data-loss prevention for bodies.

## Outbound network boundary

Replay cannot choose a URL. The target is fixed by startup configuration; URL credentials and non-HTTP schemes are rejected; redirects and environment proxies are disabled; and the default dialer blocks non-public resolved addresses. Disabling proxy inheritance is part of the SSRF boundary because a proxy could otherwise resolve and connect outside the checked dialer. DNS is resolved at connection time. Hop-by-hop and spoofable proxy/Relaybox identity headers are stripped. `-allow-private-targets` deliberately disables the destination-IP boundary for controlled development only.

## Durability and resource boundary

When forwarding is configured, the capture and initial forwarding intent are one synced record before acknowledgement. Workers claim durable jobs with ownership and expiry; attempts and resulting job states are also one record. A full/lost wake-up hint cannot lose work because workers poll storage. Startup recovers leases from the prior process, and normal operation reclaims expired leases.

Delivery remains at least once. A crash after a destination processes a request but before success is durable can repeat it. Delivery IDs and body hashes suppress capture duplicates but are operational idempotency keys, not authorization. Downstream receivers should deduplicate Relaybox request/job IDs.

Bodies, body reads, body-search prefixes, search scans, result pages, event catch-up, subscriber buffers, response capture, attempts, jobs, captures, and the compaction threshold have configured bounds. Completed data is evicted oldest first; unfinished delivery work is never evicted to admit a new capture. The service has no sustained request-rate limiter, tenant isolation, or quota partitioning, so network-level rate controls are still required for exposed deployments.
