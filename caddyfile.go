// Copyright 2026 Pieter Berkel
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ratelimitissuer

import (
	"strconv"
	"strings"

	"github.com/caddyserver/certmagic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// UnmarshalCaddyfile populates RateLimitIssuer from Caddyfile tokens.
//
// Syntax:
//
//	issuer rate_limit {
//	    issuer              <module> { ... }
//	    rate_limit   <limit> <duration>
//	    per_domain_rate_limit <limit> <duration>
//	}
//
// issuer is required. rate_limit and per_domain_rate_limit may be
// repeated for tiered limits; all windows must have capacity for issuance to
// proceed.
//
// Example:
//
//	issuer rate_limit {
//	    issuer acme {
//	        dir https://acme-v02.api.letsencrypt.org/directory
//	    }
//	    rate_limit   100 1h
//	    rate_limit   500 24h
//	    per_domain_rate_limit 5  6h
//	    per_domain_rate_limit 20 24h
//	}
func (iss *RateLimitIssuer) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume "rate_limit"
	if d.NextArg() {
		return d.ArgErr()
	}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "issuer":
			if iss.IssuerRaw != nil {
				return d.Err("inner issuer already specified")
			}
			raw, err := unmarshalIssuer(d)
			if err != nil {
				return err
			}
			iss.IssuerRaw = raw

		case "rate_limit":
			args := d.RemainingArgs()
			if len(args) != 2 {
				return d.Err("rate_limit requires exactly two arguments: <limit> <duration>")
			}
			iss.RateLimit = append(iss.RateLimit, makeCaddyRateLimit(args[0], args[1]))

		case "per_domain_rate_limit":
			args := d.RemainingArgs()
			if len(args) != 2 {
				return d.Err("per_domain_rate_limit requires exactly two arguments: <limit> <duration>")
			}
			iss.PerDomainRateLimit = append(iss.PerDomainRateLimit, makeCaddyRateLimit(args[0], args[1]))

		case "shared":
			if !d.NextArg() {
				return d.ArgErr()
			}
			sp := &SharedPool{Name: d.Val()}
			if d.NextArg() {
				return d.ArgErr()
			}
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				switch d.Val() {
				case "rate_limit":
					args := d.RemainingArgs()
					if len(args) != 2 {
						return d.Err("rate_limit requires exactly two arguments: <limit> <duration>")
					}
					sp.RateLimit = append(sp.RateLimit, makeCaddyRateLimit(args[0], args[1]))
				case "per_domain_rate_limit":
					args := d.RemainingArgs()
					if len(args) != 2 {
						return d.Err("per_domain_rate_limit requires exactly two arguments: <limit> <duration>")
					}
					sp.PerDomainRateLimit = append(sp.PerDomainRateLimit, makeCaddyRateLimit(args[0], args[1]))
				default:
					return d.Errf("unknown subdirective '%s'", d.Val())
				}
			}
			iss.SharedPools = append(iss.SharedPools, sp)

		default:
			return d.Errf("unknown subdirective '%s'", d.Val())
		}
	}

	return nil
}

// unmarshalIssuer reads the next module name token, delegates Caddyfile
// parsing to that module, and returns the JSON-encoded module object.
func unmarshalIssuer(d *caddyfile.Dispenser) ([]byte, error) {
	if !d.NextArg() {
		return nil, d.ArgErr()
	}
	modName := d.Val()
	modID := "tls.issuance." + modName

	unm, err := caddyfile.UnmarshalModule(d, modID)
	if err != nil {
		return nil, err
	}
	issuer, ok := unm.(certmagic.Issuer)
	if !ok {
		return nil, d.Errf("module %s (%T) is not a certmagic.Issuer", modID, unm)
	}
	return caddyconfig.JSONModuleObject(issuer, "module", modName, nil), nil
}

// makeCaddyRateLimit constructs a RateLimit from Caddyfile token strings.
// Plain integers and durations are parsed immediately; placeholder expressions
// are stored in the Raw fields for deferred resolution during provisioning.
func makeCaddyRateLimit(limitVal, durationVal string) *RateLimit {
	rl := &RateLimit{}
	if strings.Contains(limitVal, "{") {
		rl.LimitRaw = limitVal
	} else if n, err := strconv.Atoi(limitVal); err == nil {
		rl.Limit = n
	} else {
		rl.LimitRaw = limitVal // will fail at provision time with a clear error
	}
	if strings.Contains(durationVal, "{") {
		rl.DurationRaw = durationVal
	} else if d, err := caddy.ParseDuration(durationVal); err == nil {
		rl.Duration = caddy.Duration(d)
	} else {
		rl.DurationRaw = durationVal // will fail at provision time with a clear error
	}
	return rl
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*RateLimitIssuer)(nil)
)
