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

// Package ratelimitissuer provides a Caddy TLS issuer module
// (tls.issuance.rate_limit) that wraps any inner certmagic.Issuer and enforces
// configurable certificate issuance rate limits.
//
// Because limits are enforced after certmagic's SubjectTransformer has run,
// they apply to the effective certificate subject rather than the raw hostname
// from the TLS handshake. This means hostnames that share a wildcard cert
// (e.g. www.example.com and api.example.com both mapping to *.example.com)
// correctly count as one issuance rather than two.
package ratelimitissuer

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
	"golang.org/x/net/publicsuffix"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	caddy.RegisterModule(RateLimitIssuer{})
}

// RateLimitIssuer is a TLS issuer (module ID: tls.issuance.rate_limit) that
// wraps an inner certmagic.Issuer and enforces configurable issuance rate
// limits.
//
// Limits are enforced at issuance time, after certmagic's SubjectTransformer
// has run, so counts apply to the effective certificate subject — not the raw
// hostname from the TLS handshake. This makes RateLimitIssuer correct when
// used with tls.issuance.opportunistic, where multiple hostnames may map to
// the same wildcard certificate.
//
// # Multiple instances
//
// When multiple RateLimitIssuer instances are loaded into the same Caddy
// server (e.g. across different automation policies), each instance maintains
// independent in-memory rate limit windows. A certificate issuance recorded by
// one instance does not advance the sliding window of another, so the effective
// combined rate may be higher than the configured per-instance limit.
//
// EXPERIMENTAL: Subject to change.
type RateLimitIssuer struct {
	// The inner issuer to delegate certificate issuance to.
	// Any tls.issuance module is accepted. Required.
	IssuerRaw json.RawMessage `json:"issuer,omitempty" caddy:"namespace=tls.issuance inline_key=module"`

	// Global issuance rate limits across all domains. Each entry enforces an
	// independent sliding window; all windows must have capacity for issuance
	// to proceed. Multiple entries allow tiered limits (e.g. 100/hour and
	// 500/day simultaneously).
	GlobalRateLimit []*RateLimit `json:"global_rate_limit,omitempty"`

	// Per registrable domain issuance rate limits. Each entry enforces an
	// independent sliding window per domain; all windows must have capacity.
	// Multiple entries allow tiered limits (e.g. 5/6h and 20/day per domain).
	PerDomainRateLimit []*RateLimit `json:"per_domain_rate_limit,omitempty"`

	issuer      certmagic.Issuer
	logger      *zap.Logger
	rateLimiter *rateLimitState
}

// CaddyModule returns the Caddy module information.
func (RateLimitIssuer) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.issuance.rate_limit",
		New: func() caddy.Module { return new(RateLimitIssuer) },
	}
}

// Provision sets up the module.
func (iss *RateLimitIssuer) Provision(ctx caddy.Context) error {
	iss.logger = ctx.Logger()

	repl := caddy.NewReplacer()

	for _, rl := range iss.GlobalRateLimit {
		if err := rl.resolve(repl, "global_rate_limit"); err != nil {
			return err
		}
		if err := rl.validate("global_rate_limit"); err != nil {
			return err
		}
	}
	for _, rl := range iss.PerDomainRateLimit {
		if err := rl.resolve(repl, "per_domain_rate_limit"); err != nil {
			return err
		}
		if err := rl.validate("per_domain_rate_limit"); err != nil {
			return err
		}
	}

	globals := make([]*slidingWindow, len(iss.GlobalRateLimit))
	for i := range globals {
		globals[i] = &slidingWindow{}
	}
	iss.rateLimiter = &rateLimitState{
		globalLimits:    iss.GlobalRateLimit,
		perDomainLimits: iss.PerDomainRateLimit,
		globals:         globals,
		domains:         make(map[string][]*slidingWindow),
		now:             time.Now,
	}

	if iss.IssuerRaw != nil {
		val, err := ctx.LoadModule(iss, "IssuerRaw")
		if err != nil {
			return fmt.Errorf("loading inner issuer module: %v", err)
		}
		iss.issuer = val.(certmagic.Issuer)
	}
	if iss.issuer == nil {
		return fmt.Errorf("inner issuer is required")
	}

	return nil
}

// SetConfig implements caddytls.ConfigSetter. It propagates the certmagic
// config to the inner issuer.
func (iss *RateLimitIssuer) SetConfig(cfg *certmagic.Config) {
	if cs, ok := iss.issuer.(caddytls.ConfigSetter); ok {
		cs.SetConfig(cfg)
	}
}

// PreCheck implements certmagic.PreChecker. It performs fast in-memory rate
// limit checks to reject requests early — before the inner issuer sets up
// challenge infrastructure — then delegates to the inner issuer's PreCheck if
// present.
//
// Rate limit errors are wrapped in certmagic.ErrNoRetry so that the TLS
// handshake fails immediately rather than blocking in certmagic's obtain loop.
func (iss *RateLimitIssuer) PreCheck(ctx context.Context, names []string, interactive bool) error {
	if err := iss.checkRateLimits(names); err != nil {
		return certmagic.ErrNoRetry{Err: err}
	}
	if pc, ok := iss.issuer.(certmagic.PreChecker); ok {
		return pc.PreCheck(ctx, names, interactive)
	}
	return nil
}

// Issue obtains a certificate via the inner issuer. Rate limit counters are
// recorded only on successful issuance; a failed issuance does not consume a
// slot.
func (iss *RateLimitIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	cert, err := iss.issuer.Issue(ctx, csr)
	if err != nil {
		return nil, err
	}
	iss.recordIssuance(csr.DNSNames)
	return cert, nil
}

// IssuerKey delegates to the inner issuer's key for certificate storage namespacing.
func (iss *RateLimitIssuer) IssuerKey() string {
	return iss.issuer.IssuerKey()
}

// GetRenewalInfo implements certmagic.RenewalInfoGetter by delegating to the
// inner issuer, if it supports ARI. This allows Caddy to fetch ACME Renewal
// Information (RFC 8739) through the rate_limit wrapper.
func (iss *RateLimitIssuer) GetRenewalInfo(ctx context.Context, cert certmagic.Certificate) (acme.RenewalInfo, error) {
	if rig, ok := iss.issuer.(certmagic.RenewalInfoGetter); ok {
		return rig.GetRenewalInfo(ctx, cert)
	}
	return acme.RenewalInfo{}, fmt.Errorf("inner issuer does not support ARI")
}

// Revoke implements certmagic.Revoker by delegating to the inner issuer,
// if it supports revocation.
func (iss *RateLimitIssuer) Revoke(ctx context.Context, cert certmagic.CertificateResource, reason int) error {
	if r, ok := iss.issuer.(certmagic.Revoker); ok {
		return r.Revoke(ctx, cert, reason)
	}
	return fmt.Errorf("inner issuer does not support revocation")
}

// checkRateLimits checks all in-memory rate limit windows.
func (iss *RateLimitIssuer) checkRateLimits(names []string) error {
	if len(iss.GlobalRateLimit) > 0 {
		if err := iss.rateLimiter.checkGlobal(); err != nil {
			return err
		}
	}
	if len(iss.PerDomainRateLimit) > 0 {
		for _, domain := range iss.uniqueDomains(names) {
			if err := iss.rateLimiter.checkDomain(domain); err != nil {
				return err
			}
		}
	}
	return nil
}

// recordIssuance records a successful certificate issuance in all rate limit
// counters.
func (iss *RateLimitIssuer) recordIssuance(names []string) {
	if len(iss.GlobalRateLimit) > 0 {
		iss.rateLimiter.recordGlobal()
	}
	if len(iss.PerDomainRateLimit) > 0 {
		for _, domain := range iss.uniqueDomains(names) {
			iss.rateLimiter.recordDomain(domain)
		}
	}
}

// uniqueDomains extracts unique registrable domains (eTLD+1) from names.
// Names that cannot be parsed are skipped with a warning.
func (iss *RateLimitIssuer) uniqueDomains(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	result := make([]string, 0, len(names))
	for _, name := range names {
		domain, err := certDomain(name)
		if err != nil {
			iss.logger.Warn("skipping unparseable certificate name",
				zap.String("name", name),
				zap.Error(err))
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		result = append(result, domain)
	}
	return result
}

// certDomain returns the registrable domain (eTLD+1) for a certificate name.
func certDomain(name string) (string, error) {
	lookup := strings.TrimPrefix(name, "*.")
	domain, err := publicsuffix.EffectiveTLDPlusOne(lookup)
	if err != nil {
		return "", fmt.Errorf("determining registrable domain for %q: %w", name, err)
	}
	return domain, nil
}

// Interface guards
var (
	_ caddy.Module                = (*RateLimitIssuer)(nil)
	_ caddy.Provisioner           = (*RateLimitIssuer)(nil)
	_ certmagic.Issuer            = (*RateLimitIssuer)(nil)
	_ certmagic.PreChecker        = (*RateLimitIssuer)(nil)
	_ certmagic.Revoker           = (*RateLimitIssuer)(nil)
	_ certmagic.RenewalInfoGetter = (*RateLimitIssuer)(nil)
	_ caddytls.ConfigSetter       = (*RateLimitIssuer)(nil)
)
