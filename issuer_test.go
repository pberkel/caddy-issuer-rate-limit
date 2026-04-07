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
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
)

// --- Helpers ----------------------------------------------------------------

// stubIssuer is a minimal certmagic.Issuer for testing.
type stubIssuer struct {
	key       string
	issueFunc func(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error)
}

func (s *stubIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
	if s.issueFunc != nil {
		return s.issueFunc(ctx, csr)
	}
	return &certmagic.IssuedCertificate{Certificate: []byte("stub")}, nil
}

func (s *stubIssuer) IssuerKey() string {
	if s.key != "" {
		return s.key
	}
	return "stub"
}

// preCheckerIssuer wraps stubIssuer with a PreCheck hook.
type preCheckerIssuer struct {
	stubIssuer
	preCheckErr error
	called      bool
}

func (p *preCheckerIssuer) PreCheck(_ context.Context, _ []string, _ bool) error {
	p.called = true
	return p.preCheckErr
}

// newTestIssuer returns a RateLimitIssuer wired with the provided inner issuer,
// with no limits configured.
func newTestIssuer(inner certmagic.Issuer) *RateLimitIssuer {
	return &RateLimitIssuer{
		issuer: inner,
		rateLimiter: &rateLimitState{
			domains: make(map[string][]*slidingWindow),
			now:     time.Now,
		},
	}
}

// newTestIssuerWithLimits returns a RateLimitIssuer with optional rate limits
// configured.
func newTestIssuerWithLimits(inner certmagic.Issuer, globalRL, perDomainRL *RateLimit) *RateLimitIssuer {
	iss := newTestIssuer(inner)
	if globalRL != nil {
		iss.GlobalRateLimit = []*RateLimit{globalRL}
		iss.rateLimiter.globalLimits = iss.GlobalRateLimit
		iss.rateLimiter.globals = []*slidingWindow{{}}
	}
	if perDomainRL != nil {
		iss.PerDomainRateLimit = []*RateLimit{perDomainRL}
		iss.rateLimiter.perDomainLimits = iss.PerDomainRateLimit
	}
	return iss
}

func makeRateLimit(limit int, d time.Duration) *RateLimit {
	return &RateLimit{Limit: limit, Duration: caddy.Duration(d)}
}

// --- certDomain -------------------------------------------------------------

func TestCertDomain(t *testing.T) {
	tests := []struct {
		name          string
		wantDomain    string
		wantErrSubstr string
	}{
		{"www.example.com", "example.com", ""},
		{"api.example.com", "example.com", ""},
		{"example.com", "example.com", ""},
		{"*.example.com", "example.com", ""},
		{"*.example.co.uk", "example.co.uk", ""},
		{"api.v2.example.com", "example.com", ""},
		{"com", "", "determining registrable domain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			domain, err := certDomain(tt.name)
			if tt.wantErrSubstr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrSubstr) {
					t.Fatalf("certDomain(%q) error = %v, want containing %q", tt.name, err, tt.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("certDomain(%q) unexpected error: %v", tt.name, err)
			}
			if domain != tt.wantDomain {
				t.Errorf("domain = %q, want %q", domain, tt.wantDomain)
			}
		})
	}
}

// --- checkRateLimits --------------------------------------------------------

func TestCheckRateLimits_NoLimits(t *testing.T) {
	iss := newTestIssuer(&stubIssuer{})
	if err := iss.checkRateLimits([]string{"www.example.com"}); err != nil {
		t.Errorf("unexpected error with no limits configured: %v", err)
	}
}

func TestCheckRateLimits_GlobalRateLimitExceeded(t *testing.T) {
	iss := newTestIssuerWithLimits(&stubIssuer{}, makeRateLimit(1, time.Hour), nil)
	iss.rateLimiter.recordGlobal()

	if err := iss.checkRateLimits([]string{"www.example.com"}); err == nil {
		t.Error("expected global rate limit error")
	}
}

func TestCheckRateLimits_PerDomainRateLimitExceeded(t *testing.T) {
	iss := newTestIssuerWithLimits(&stubIssuer{}, nil, makeRateLimit(1, time.Hour))
	iss.rateLimiter.recordDomain("example.com")

	if err := iss.checkRateLimits([]string{"www.example.com"}); err == nil {
		t.Error("expected per-domain rate limit error")
	}
}

func TestCheckRateLimits_DeduplicatesDomains(t *testing.T) {
	iss := newTestIssuerWithLimits(&stubIssuer{}, nil, makeRateLimit(2, time.Hour))
	iss.rateLimiter.recordDomain("example.com") // count = 1

	if err := iss.checkRateLimits([]string{"www.example.com", "api.example.com"}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- PreCheck ---------------------------------------------------------------

func TestPreCheck_DelegatesToInnerPreChecker(t *testing.T) {
	inner := &preCheckerIssuer{}
	iss := newTestIssuer(inner)

	if err := iss.PreCheck(context.Background(), []string{"www.example.com"}, false); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !inner.called {
		t.Error("inner PreCheck was not called")
	}
}

func TestPreCheck_InnerPreCheckerError(t *testing.T) {
	inner := &preCheckerIssuer{preCheckErr: errors.New("inner says no")}
	iss := newTestIssuer(inner)

	if err := iss.PreCheck(context.Background(), []string{"www.example.com"}, false); err == nil {
		t.Error("expected error from inner PreChecker")
	}
}

func TestPreCheck_RateLimitBlocksBeforeInner(t *testing.T) {
	inner := &preCheckerIssuer{}
	iss := newTestIssuerWithLimits(inner, makeRateLimit(1, time.Hour), nil)
	iss.rateLimiter.recordGlobal()

	if err := iss.PreCheck(context.Background(), []string{"www.example.com"}, false); err == nil {
		t.Error("expected rate limit error")
	}
	if inner.called {
		t.Error("inner PreCheck should not have been called when rate limit exceeded")
	}
}

func TestPreCheck_RateLimitError_IsErrNoRetry(t *testing.T) {
	iss := newTestIssuerWithLimits(&stubIssuer{}, makeRateLimit(1, time.Hour), nil)
	iss.rateLimiter.recordGlobal()

	err := iss.PreCheck(context.Background(), []string{"www.example.com"}, false)
	if err == nil {
		t.Fatal("expected error")
	}
	var noRetry certmagic.ErrNoRetry
	if !errors.As(err, &noRetry) {
		t.Errorf("expected certmagic.ErrNoRetry, got %T: %v", err, err)
	}
}

// --- Issue ------------------------------------------------------------------

func TestIssue_Success(t *testing.T) {
	iss := newTestIssuer(&stubIssuer{})
	csr := &x509.CertificateRequest{DNSNames: []string{"www.example.com"}}
	cert, err := iss.Issue(context.Background(), csr)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
}

func TestIssue_InnerError_NoCountRecorded(t *testing.T) {
	inner := &stubIssuer{
		issueFunc: func(_ context.Context, _ *x509.CertificateRequest) (*certmagic.IssuedCertificate, error) {
			return nil, errors.New("ACME failed")
		},
	}
	iss := newTestIssuerWithLimits(inner, makeRateLimit(10, time.Hour), makeRateLimit(10, time.Hour))

	if _, err := iss.Issue(context.Background(), &x509.CertificateRequest{DNSNames: []string{"www.example.com"}}); err == nil {
		t.Fatal("expected error from inner issuer")
	}

	iss.rateLimiter.mu.Lock()
	globalCount := iss.rateLimiter.globals[0].count(time.Now(), time.Hour)
	_, hasDomain := iss.rateLimiter.domains["example.com"]
	iss.rateLimiter.mu.Unlock()

	if globalCount != 0 {
		t.Errorf("global rate counter = %d after failed issuance, want 0", globalCount)
	}
	if hasDomain {
		t.Error("per-domain counter should not be recorded after failed issuance")
	}
}

func TestIssue_RecordsCountersOnSuccess(t *testing.T) {
	iss := newTestIssuerWithLimits(&stubIssuer{}, makeRateLimit(100, time.Hour), makeRateLimit(10, time.Hour))

	if _, err := iss.Issue(context.Background(), &x509.CertificateRequest{DNSNames: []string{"www.example.com"}}); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	iss.rateLimiter.mu.Lock()
	globalCount := iss.rateLimiter.globals[0].count(time.Now(), time.Duration(iss.GlobalRateLimit[0].Duration))
	domainWindows, hasDomain := iss.rateLimiter.domains["example.com"]
	var domainCount int
	if hasDomain {
		domainCount = domainWindows[0].count(time.Now(), time.Duration(iss.PerDomainRateLimit[0].Duration))
	}
	iss.rateLimiter.mu.Unlock()

	if globalCount != 1 {
		t.Errorf("global rate counter = %d, want 1", globalCount)
	}
	if !hasDomain || domainCount != 1 {
		t.Error("per-domain rate counter not incremented")
	}
}

// --- IssuerKey --------------------------------------------------------------

func TestIssuerKey(t *testing.T) {
	iss := newTestIssuer(&stubIssuer{key: "my-issuer"})
	if got := iss.IssuerKey(); got != "my-issuer" {
		t.Errorf("IssuerKey = %q, want %q", got, "my-issuer")
	}
}

// --- SetConfig --------------------------------------------------------------

type configSetterIssuer struct {
	stubIssuer
	setCalled bool
	cfg       *certmagic.Config
}

func (c *configSetterIssuer) SetConfig(cfg *certmagic.Config) {
	c.setCalled = true
	c.cfg = cfg
}

func TestSetConfig_Propagated(t *testing.T) {
	inner := &configSetterIssuer{}
	iss := newTestIssuer(inner)
	cfg := &certmagic.Config{}
	iss.SetConfig(cfg)

	if !inner.setCalled {
		t.Error("SetConfig not propagated to inner issuer")
	}
	if inner.cfg != cfg {
		t.Error("wrong config propagated to inner issuer")
	}
}

func TestSetConfig_NonSetterInnerIsOK(t *testing.T) {
	iss := newTestIssuer(&stubIssuer{})
	// Should not panic when inner issuer does not implement ConfigSetter.
	iss.SetConfig(&certmagic.Config{})
}
