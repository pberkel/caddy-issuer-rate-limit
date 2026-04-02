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
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// RateLimit defines an exact sliding-window rate limit: at most Limit
// issuances within any rolling Duration window.
type RateLimit struct {
	// Maximum number of certificate issuances within Duration.
	Limit int `json:"limit,omitempty"`
	// Rolling time window for the rate limit.
	Duration caddy.Duration `json:"duration,omitempty"`

	// LimitRaw and DurationRaw hold raw string values set during Caddyfile
	// parsing; they may contain Caddy placeholders resolved at provisioning
	// time. When non-empty, they take precedence over Limit and Duration and
	// must survive JSON serialization so that the Caddyfile → JSON → provision
	// round-trip preserves placeholder expressions.
	LimitRaw    string `json:"limit_raw,omitempty"`
	DurationRaw string `json:"duration_raw,omitempty"`
}

// rateLimitState holds in-memory exact sliding-window counters for global and
// per-domain rate limits.
type rateLimitState struct {
	mu             sync.Mutex
	global         slidingWindow
	domains        map[string]*slidingWindow
	globalLimit    *RateLimit
	perDomainLimit *RateLimit
	now            func() time.Time
}

// slidingWindow tracks exact issuance timestamps within a rolling time window.
// Timestamps are always appended in chronological order, so trimming expired
// entries is a binary search from the front. A zero-value slidingWindow is
// ready to use.
type slidingWindow struct {
	timestamps []time.Time
}

// trim removes timestamps older than d from the front of the window.
// Timestamps are always appended in chronological order, so expired entries
// are always a contiguous prefix. Compaction is done in-place to release
// the backing array slots occupied by expired entries.
func (w *slidingWindow) trim(now time.Time, d time.Duration) {
	cutoff := now.Add(-d)
	i := 0
	for i < len(w.timestamps) && !w.timestamps[i].After(cutoff) {
		i++
	}
	if i > 0 {
		w.timestamps = w.timestamps[:copy(w.timestamps, w.timestamps[i:])]
	}
}

// count returns the exact number of issuances within the past d.
func (w *slidingWindow) count(now time.Time, d time.Duration) int {
	w.trim(now, d)
	return len(w.timestamps)
}

// add records a new issuance at now, trimming expired entries first.
func (w *slidingWindow) add(now time.Time, d time.Duration) {
	w.trim(now, d)
	w.timestamps = append(w.timestamps, now)
}

// checkGlobal returns an error if the global rate limit is exceeded.
func (s *rateLimitState) checkGlobal() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := time.Duration(s.globalLimit.Duration)
	if s.global.count(s.now(), d) >= s.globalLimit.Limit {
		return fmt.Errorf("global certificate issuance rate limit exceeded")
	}
	return nil
}

// recordGlobal increments the global issuance counter.
func (s *rateLimitState) recordGlobal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.global.add(s.now(), time.Duration(s.globalLimit.Duration))
}

// checkDomain returns an error if the per-domain rate limit is exceeded for
// the given registrable domain. Expired domain windows are evicted lazily.
func (s *rateLimitState) checkDomain(domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.domains[domain]
	if !ok {
		return nil
	}
	d := time.Duration(s.perDomainLimit.Duration)
	n := w.count(s.now(), d)
	if n == 0 {
		delete(s.domains, domain)
		return nil
	}
	if n >= s.perDomainLimit.Limit {
		return fmt.Errorf("per-domain certificate issuance rate limit exceeded for %s", domain)
	}
	return nil
}

// recordDomain increments the per-domain issuance counter for domain.
func (s *rateLimitState) recordDomain(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.domains[domain]
	if !ok {
		w = &slidingWindow{}
		s.domains[domain] = w
	}
	w.add(s.now(), time.Duration(s.perDomainLimit.Duration))
}

// resolve replaces Caddy placeholders in LimitRaw and DurationRaw and stores
// the parsed values in Limit and Duration. It is a no-op when rl is nil or
// LimitRaw is empty.
func (rl *RateLimit) resolve(replacer *caddy.Replacer, name string) error {
	if rl == nil || rl.LimitRaw == "" {
		return nil
	}
	limitStr := replacer.ReplaceAll(rl.LimitRaw, "")
	limit, err := strconv.Atoi(limitStr)
	if err != nil {
		return fmt.Errorf("invalid integer value for %s limit: %s", name, limitStr)
	}
	durStr := replacer.ReplaceAll(rl.DurationRaw, "")
	dur, err := caddy.ParseDuration(durStr)
	if err != nil {
		return fmt.Errorf("invalid duration value for %s: %s", name, durStr)
	}
	rl.Limit = limit
	rl.Duration = caddy.Duration(dur)
	return nil
}

// validate returns an error if the rate limit configuration is invalid.
// It is a no-op when rl is nil.
func (rl *RateLimit) validate(name string) error {
	if rl == nil {
		return nil
	}
	if rl.Limit <= 0 {
		return fmt.Errorf("%s limit must be greater than 0, got %d", name, rl.Limit)
	}
	if time.Duration(rl.Duration) <= 0 {
		return fmt.Errorf("%s duration must be greater than 0", name)
	}
	return nil
}
