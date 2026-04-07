# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `tls.issuance.rate_limit` Caddy module wrapping any inner `tls.issuance` issuer
- Sliding-window rate limit (`rate_limit`) capping total certificate issuances across all domains within a rolling time window
- Per-domain sliding-window rate limit (`per_domain_rate_limit`) capping issuances per registrable domain (eTLD+1) within a rolling time window
- Both rate limit types support multiple entries per block for tiered limits; all windows must have capacity for issuance to proceed
- Exact sliding-window rate limiter using per-timestamp accounting (no approximation)
- Counters recorded only on successful issuance; a failed or rejected issuance does not consume a slot
- Rate limit errors wrapped in `certmagic.ErrNoRetry` to fail TLS handshakes immediately
- ARI support (`GetRenewalInfo`) delegating to the inner issuer (RFC 8739)
- Revocation support (`Revoke`) delegating to the inner issuer
- Caddyfile support: `issuer rate_limit { ... }`
- Caddy placeholder support in all numeric and duration configuration values
- `PreCheck` fast-path rejects requests before the inner issuer sets up challenge infrastructure
