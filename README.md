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
            global_rate_limit     100 1h
            global_rate_limit     500 24h
            per_domain_rate_limit 5   6h
            per_domain_rate_limit 20  24h
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
| `global_rate_limit <limit> <duration>` | No | Maximum new certificates across all domains within a rolling time window (e.g. `100 1h`). May be specified multiple times for tiered limits; all windows must have capacity. |
| `per_domain_rate_limit <limit> <duration>` | No | Maximum new certificates per registrable domain within a rolling time window (e.g. `5 6h`). May be specified multiple times for tiered limits; all windows must have capacity. |

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
                "global_rate_limit": [
                  { "limit": 100, "duration": 3600000000000 },
                  { "limit": 500, "duration": 86400000000000 }
                ],
                "per_domain_rate_limit": [
                  { "limit": 5,  "duration": 21600000000000 },
                  { "limit": 20, "duration": 86400000000000 }
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

Both `global_rate_limit` and `per_domain_rate_limit` may be specified multiple times. Each entry defines an independent sliding window — an issuance must fit within **all** configured windows to proceed. This enables tiered constraints such as "no more than 5 per domain per 6 hours, and no more than 20 per domain per day".

### Multiple instances

When multiple `rate_limit` instances are loaded into the same Caddy server, each maintains independent in-memory windows. A certificate issuance recorded by one instance does not advance the sliding window of another.

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
            global_rate_limit     100 1h
            global_rate_limit     500 24h
            per_domain_rate_limit 5   6h
            per_domain_rate_limit 20  24h
        }
    }
}
```

This separation of concerns keeps admission (is this hostname allowed?) distinct from lifecycle (how many certificates have been issued?).

## License

Apache 2.0 — see [LICENSE](LICENSE).
