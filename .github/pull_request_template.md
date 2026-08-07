# Pull request

## Summary

Describe the problem and the smallest focused change that solves it.

## Verification

- [ ] `gofmt` is clean.
- [ ] Tests, race tests, vet, Staticcheck, and vulnerability scanning pass.
- [ ] Behavior changes include regression tests.
- [ ] Storage changes preserve existing append-log recovery and monotonic sequences.
- [ ] Release changes preserve the exact six-target pre-publication validation.
- [ ] Relevant README, operations, architecture, threat-model, or release documentation is updated.

## Security and compatibility

Describe any effect on authentication, redaction, SSRF defenses, durability, at-least-once delivery, resource bounds, on-disk compatibility, or release artifacts. Write “none” when there is no effect.
