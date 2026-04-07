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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

// SharedPool defines rate limits for a named pool that can be shared across
// multiple RateLimitIssuer instances within the same Caddy process. Instances
// referencing the same Name share in-memory sliding windows. State is persisted
// to Caddy's configured storage backend and restored on startup.
//
// Use the conventional name "global" to create a process-wide limit that all
// rate_limit instances opt into:
//
//	shared global {
//	    rate_limit            500 24h
//	    per_domain_rate_limit  20 24h
//	}
type SharedPool struct {
	// Name identifies this pool. Instances referencing the same name share
	// rate limit state. Must not be empty or contain path separators. Required.
	Name string `json:"name"`

	// Issuance rate limits across all domains for this pool. Each entry
	// enforces an independent sliding window; all windows must have capacity
	// for issuance to proceed. Multiple entries allow tiered limits.
	RateLimit []*RateLimit `json:"rate_limit,omitempty"`

	// Per registrable domain issuance rate limits for this pool. Each entry
	// enforces an independent sliding window per domain; all windows must have
	// capacity. Multiple entries allow tiered limits.
	PerDomainRateLimit []*RateLimit `json:"per_domain_rate_limit,omitempty"`
}

func (sp *SharedPool) resolve(repl *caddy.Replacer) error {
	prefix := fmt.Sprintf("shared[%q]", sp.Name)
	for _, rl := range sp.RateLimit {
		if err := rl.resolve(repl, prefix+".rate_limit"); err != nil {
			return err
		}
	}
	for _, rl := range sp.PerDomainRateLimit {
		if err := rl.resolve(repl, prefix+".per_domain_rate_limit"); err != nil {
			return err
		}
	}
	return nil
}

func (sp *SharedPool) validate() error {
	if err := validatePoolName(sp.Name); err != nil {
		return err
	}
	if len(sp.RateLimit) == 0 && len(sp.PerDomainRateLimit) == 0 {
		return fmt.Errorf("shared pool %q: at least one rate limit is required", sp.Name)
	}
	prefix := fmt.Sprintf("shared[%q]", sp.Name)
	for _, rl := range sp.RateLimit {
		if err := rl.validate(prefix + ".rate_limit"); err != nil {
			return err
		}
	}
	for _, rl := range sp.PerDomainRateLimit {
		if err := rl.validate(prefix + ".per_domain_rate_limit"); err != nil {
			return err
		}
	}
	return nil
}

// validatePoolName returns an error if name is unsuitable as a storage path
// component.
func validatePoolName(name string) error {
	if name == "" {
		return fmt.Errorf("pool name must not be empty")
	}
	if strings.ContainsAny(name, "/\\") || name == "." || name == ".." {
		return fmt.Errorf("pool name %q must not contain path separators", name)
	}
	return nil
}

// registryEntry is a process-lifetime record for a named shared pool.
type registryEntry struct {
	mu     sync.Mutex
	state  *rateLimitState
	pool   *SharedPool
	loaded bool // true once persisted state has been applied from storage
}

// processRegistry holds named pool entries keyed by pool name.
var processRegistry sync.Map // map[string]*registryEntry

// getOrRegisterPool returns the registry entry for sp.Name, creating one if
// none exists. If an existing entry has different limits it is replaced (reset)
// and a warning is logged.
func getOrRegisterPool(sp *SharedPool, logger *zap.Logger) *registryEntry {
	candidate := newRegistryEntry(sp)
	actual, loaded := processRegistry.LoadOrStore(sp.Name, candidate)
	entry := actual.(*registryEntry)
	if loaded && !poolLimitsMatch(entry.pool, sp) {
		logger.Warn("shared pool limits changed; resetting rate limit state",
			zap.String("pool", sp.Name))
		processRegistry.Store(sp.Name, candidate)
		return candidate
	}
	return entry
}

func newRegistryEntry(sp *SharedPool) *registryEntry {
	globals := make([]*slidingWindow, len(sp.RateLimit))
	for i := range globals {
		globals[i] = &slidingWindow{}
	}
	return &registryEntry{
		state: &rateLimitState{
			globalLimits:    sp.RateLimit,
			perDomainLimits: sp.PerDomainRateLimit,
			globals:         globals,
			domains:         make(map[string][]*slidingWindow),
			now:             time.Now,
		},
		pool: sp,
	}
}

// poolLimitsMatch returns true if a and b have identical limit configurations.
func poolLimitsMatch(a, b *SharedPool) bool {
	if len(a.RateLimit) != len(b.RateLimit) || len(a.PerDomainRateLimit) != len(b.PerDomainRateLimit) {
		return false
	}
	for i := range a.RateLimit {
		if a.RateLimit[i].Limit != b.RateLimit[i].Limit || a.RateLimit[i].Duration != b.RateLimit[i].Duration {
			return false
		}
	}
	for i := range a.PerDomainRateLimit {
		if a.PerDomainRateLimit[i].Limit != b.PerDomainRateLimit[i].Limit || a.PerDomainRateLimit[i].Duration != b.PerDomainRateLimit[i].Duration {
			return false
		}
	}
	return true
}

// persistedPoolState is the serialisable form of a pool's sliding window state.
type persistedPoolState struct {
	// Global holds timestamps for each rate_limit window, ordered to match
	// the pool's RateLimit slice.
	Global [][]time.Time `json:"global,omitempty"`
	// Domains maps registrable domain to per_domain_rate_limit window
	// timestamps, ordered to match the pool's PerDomainRateLimit slice.
	Domains map[string][][]time.Time `json:"domains,omitempty"`
}

// poolStorageKey returns the storage key for a named pool.
func poolStorageKey(name string) string {
	return "tls_issuer_rate_limit/pools/" + name + ".json"
}

// loadAndApplyPoolState loads persisted state from storage and merges it into
// entry.state. Must be called with entry.mu held.
func loadAndApplyPoolState(ctx context.Context, storage certmagic.Storage, entry *registryEntry, logger *zap.Logger) {
	data, err := storage.Load(ctx, poolStorageKey(entry.pool.Name))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			logger.Warn("failed to load persisted pool state",
				zap.String("pool", entry.pool.Name), zap.Error(err))
		}
		return
	}
	var ps persistedPoolState
	if err := json.Unmarshal(data, &ps); err != nil {
		logger.Warn("failed to decode persisted pool state; starting fresh",
			zap.String("pool", entry.pool.Name), zap.Error(err))
		return
	}
	applyPersistedState(entry.state, &ps)
}

// applyPersistedState merges ps into state. Only as many windows as the current
// config defines are populated; extra persisted windows are ignored. Expired
// timestamps are trimmed lazily on first use by count().
func applyPersistedState(state *rateLimitState, ps *persistedPoolState) {
	state.mu.Lock()
	defer state.mu.Unlock()
	for i := range state.globals {
		if i < len(ps.Global) {
			state.globals[i].timestamps = append(state.globals[i].timestamps, ps.Global[i]...)
		}
	}
	for domain, windowTimestamps := range ps.Domains {
		if len(windowTimestamps) == 0 {
			continue
		}
		windows := make([]*slidingWindow, len(state.perDomainLimits))
		for i := range windows {
			windows[i] = &slidingWindow{}
			if i < len(windowTimestamps) {
				windows[i].timestamps = append(windows[i].timestamps, windowTimestamps[i]...)
			}
		}
		state.domains[domain] = windows
	}
}

// savePoolState serialises entry's current window state to storage. Expired
// timestamps are pruned before saving. Errors are logged but not returned
// (best-effort).
func savePoolState(ctx context.Context, storage certmagic.Storage, entry *registryEntry, logger *zap.Logger) {
	entry.state.mu.Lock()
	now := entry.state.now()

	global := make([][]time.Time, len(entry.pool.RateLimit))
	for i, rl := range entry.pool.RateLimit {
		entry.state.globals[i].trim(now, time.Duration(rl.Duration))
		ts := make([]time.Time, len(entry.state.globals[i].timestamps))
		copy(ts, entry.state.globals[i].timestamps)
		global[i] = ts
	}

	var domains map[string][][]time.Time
	for domain, windows := range entry.state.domains {
		domainTs := make([][]time.Time, len(entry.pool.PerDomainRateLimit))
		allEmpty := true
		for i, rl := range entry.pool.PerDomainRateLimit {
			windows[i].trim(now, time.Duration(rl.Duration))
			if len(windows[i].timestamps) > 0 {
				allEmpty = false
			}
			ts := make([]time.Time, len(windows[i].timestamps))
			copy(ts, windows[i].timestamps)
			domainTs[i] = ts
		}
		if !allEmpty {
			if domains == nil {
				domains = make(map[string][][]time.Time)
			}
			domains[domain] = domainTs
		}
	}
	entry.state.mu.Unlock()

	ps := persistedPoolState{Global: global, Domains: domains}
	data, err := json.Marshal(ps)
	if err != nil {
		logger.Warn("failed to encode pool state",
			zap.String("pool", entry.pool.Name), zap.Error(err))
		return
	}
	if err := storage.Store(ctx, poolStorageKey(entry.pool.Name), data); err != nil {
		logger.Warn("failed to save pool state",
			zap.String("pool", entry.pool.Name), zap.Error(err))
	}
}
