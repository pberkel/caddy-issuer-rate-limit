# caddy-issuer-rate-limit

A [Caddy](https://caddyserver.com) TLS issuer module (`tls.issuance.rate_limit`) that wraps any inner issuer and enforces configurable certificate issuance rate limits.

> **Experimental:** The configuration interface may change before a stable release.

## Why this module exists

Caddy's on-demand TLS permission module runs before `SubjectTransformer` is applied, meaning it operates on raw hostnames from the TLS handshake rather than actual certificate subjects. For deployments that use wildcard subject transformation (e.g. via [`caddy-issuer-opportunistic`](https://github.com/pberkel/caddy-issuer-opportunistic)), this causes over-counting: `www.example.com` and `api.example.com` each consume a slot even though both result in a single `*.example.com` certificate.

This module enforces limits at issuance time — after `SubjectTransformer` has run — so counts always reflect actual certificates issued. Hostnames that map to the same wildcard certificate share a single slot rather than each consuming one.

## How it works

The module wraps an inner issuer and intercepts the issuance lifecycle at two points:

1. **`PreCheck`** — fast in-memory checks (rate limit windows) reject requests before the inner issuer sets up challenge infrastructure.
2. **`Issue`** — delegates to the inner issuer. Counters are recorded **only on successful issuance**; a failed issuance does not consume a slot.

## Installation

Build Caddy with this module using [`xcaddy`](https://github.com/caddyserver/xcaddy):

```sh
xcaddy build \
  --with github.com/pberkel/caddy-issuer-rate-limit
```

## Configuration

### Caddyfile

```caddyfile
{
    on_demand_tls {
        permission http {
            endpoint https://auth.example.internal/check
        }
    }
}

:443 {
    tls {
        on_demand
        issuer rate_limit {
            issuer acme {
                dir https://acme-v02.api.letsencrypt.org/directory
            }
            rate_limit             30 10m   # local
            rate_limit            300 24h   # local
            per_domain_rate_limit   5 6h    # local per-domain
            per_domain_rate_limit  20 24h   # local per-domain
            shared global {                 # shared across all instances
                rate_limit            500 24h
                per_domain_rate_limit  50 24h
            }
        }
    }
    reverse_proxy localhost:8080
}
```

#### Syntax

```
issuer rate_limit {
    ...
}
```

#### Subdirectives

| Subdirective | Required | Description |
|---|---|---|
| `issuer <module> { ... }` | Yes | Inner issuer to delegate certificate issuance to. Any `tls.issuance` module is accepted. |
| `rate_limit <limit> <duration>` | No | Maximum new certificates across all domains within a rolling time window (e.g. `100 1h`). Local to this instance. May be repeated for tiered limits; all windows must have capacity. |
| `per_domain_rate_limit <limit> <duration>` | No | Maximum new certificates per registrable domain within a rolling time window (e.g. `5 6h`). Local to this instance. May be repeated for tiered limits. |
| `shared <name> { ... }` | No | Named shared pool. Rate limit state is shared across all `rate_limit` instances referencing the same name and persisted across restarts. May be repeated for multiple pools. See [Shared pools](#shared-pools) below. |

#### `shared` block subdirectives

| Subdirective | Description |
|---|---|
| `rate_limit <limit> <duration>` | Maximum new certificates across all domains within a rolling window for this pool. May be repeated for tiered limits. |
| `per_domain_rate_limit <limit> <duration>` | Maximum new certificates per registrable domain within a rolling window for this pool. May be repeated for tiered limits. |

### JSON

```json
{
  "apps": {
    "tls": {
      "automation": {
        "on_demand": {
          "permission": {
            "module": "http",
            "endpoint": "https://auth.example.internal/check"
          }
        },
        "policies": [
          {
            "on_demand": true,
            "issuers": [
              {
                "module": "rate_limit",
                "issuer": {
                  "module": "acme",
                  "ca": "https://acme-v02.api.letsencrypt.org/directory"
                },
                "rate_limit": [
                  { "limit": 30,  "duration": 600000000000 },
                  { "limit": 300, "duration": 86400000000000 }
                ],
                "per_domain_rate_limit": [
                  { "limit": 5,  "duration": 21600000000000 },
                  { "limit": 20, "duration": 86400000000000 }
                ],
                "shared_pools": [
                  {
                    "name": "global",
                    "rate_limit": [
                      { "limit": 500, "duration": 86400000000000 }
                    ],
                    "per_domain_rate_limit": [
                      { "limit": 50, "duration": 86400000000000 }
                    ]
                  }
                ]
              }
            ]
          }
        ]
      }
    }
  }
}
```

## Rate limit behaviour

Rate limits are enforced per registrable domain (eTLD+1). Because limits apply after `SubjectTransformer` has run, hostnames that map to the same wildcard certificate share a single slot:

- `www.example.com` and `api.example.com` both transforming to `*.example.com` count as one issuance against the `example.com` per-domain limit.
- `www.example.com` and `api.example.com` issued without transformation each count independently under `example.com`.

### Tiered limits

Both `rate_limit` and `per_domain_rate_limit` may be specified multiple times. Each entry defines an independent sliding window — an issuance must fit within **all** configured windows to proceed. This enables tiered constraints such as "no more than 5 per domain per 6 hours, and no more than 20 per domain per day".

## Shared pools

Named shared pools (`shared <name> { ... }`) allow multiple `rate_limit` instances within the same Caddy process to enforce a common rate limit. All instances referencing the same pool name share in-memory sliding windows — an issuance recorded by one instance is visible to all others.

Use the conventional name `global` to create a process-wide limit that all instances participate in:

```caddyfile
shared global {
    rate_limit            500 24h
    per_domain_rate_limit  50 24h
}
```

**Multiple instances:** an issuance must satisfy **all** configured limits — local and shared — to proceed.

**Limit changes:** if a pool's limits are changed across a config reload, the in-memory state is reset and a warning is logged.

**Persistence:** shared pool state is saved to Caddy's configured storage backend on shutdown and config reload, and restored on startup. Storage key: `tls_issuer_rate_limit/pools/<name>.json`. Expired timestamps are pruned before saving.

## Recommended usage with caddy-tls-permission-policy

For on-demand TLS deployments, use [`caddy-tls-permission-policy`](https://github.com/pberkel/caddy-tls-permission-policy) for admission control (DNS resolution checks, IP filtering, hostname pattern matching) and this module for issuance rate limiting:

```caddyfile
{
    on_demand_tls {
        permission policy {
            resolves_to your-server.example.com
            max_subdomain_depth 3
        }
    }
}

:443 {
    tls {
        on_demand
        issuer rate_limit {
            issuer acme {
                dir https://acme-v02.api.letsencrypt.org/directory
            }
            rate_limit             30 10m
            rate_limit            300 24h
            per_domain_rate_limit   5 6h
            per_domain_rate_limit  20 24h
            shared global {
                rate_limit            500 24h
                per_domain_rate_limit  50 24h
            }
        }
    }
}
```

This separation of concerns keeps admission (is this hostname allowed?) distinct from lifecycle (how many certificates have been issued?).

## License

Apache 2.0 — see [LICENSE](LICENSE).
