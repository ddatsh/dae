/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package cache

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestNotExistsDedupeSemantics(t *testing.T) {
	c := &dedupeCache{seen: make(map[string]time.Time), ttl: time.Minute}

	if !c.NotExists("k1") {
		t.Fatal("first call must report true")
	}
	if c.NotExists("k1") {
		t.Fatal("second call within TTL must report false")
	}
	if c.NotExists("k1") {
		t.Fatal("third call within TTL must report false")
	}
	if !c.NotExists("k2") {
		t.Fatal("another key must not collide with k1")
	}
}

func TestNotExistsExpiresAndRefreshes(t *testing.T) {
	c := &dedupeCache{seen: make(map[string]time.Time), ttl: 10 * time.Millisecond}

	if !c.NotExists("k") {
		t.Fatal("first call must report true")
	}
	// Repeated hits refresh the TTL (deadline = last hit time + ttl).
	deadline := c.seen["k"]
	for i := 0; i < 3; i++ {
		if c.NotExists("k") {
			t.Fatal("live key must report false")
		}
	}
	if !c.seen["k"].After(deadline) {
		t.Fatalf("TTL must be refreshed on hit: %v -> %v", deadline, c.seen["k"])
	}

	time.Sleep(15 * time.Millisecond)
	if !c.NotExists("k") {
		t.Fatal("expired key must report true again")
	}

	// A sweep triggered by writes must remove expired entries.
	time.Sleep(15 * time.Millisecond)
	for i := uint64(0); i <= dedupeSweepInterval; i++ {
		c.NotExists("sweep")
	}
	c.mu.Lock()
	_, exists := c.seen["k"]
	c.mu.Unlock()
	if exists {
		t.Fatal("lazy sweep must drop expired entries")
	}
}

func TestNotExistsConcurrent(t *testing.T) {
	c := &dedupeCache{seen: make(map[string]time.Time), ttl: time.Minute}

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				c.NotExists("shared")
				c.NotExists(string(rune('a' + g)))
			}
		}(g)
	}
	wg.Wait()
}

// TestPackageCacheHasNoGoroutine pins the reason the go-cache janitor was
// replaced: the package must not own a single background goroutine, so the
// control package's goleak fence never trips on an import-time janitor.
func TestPackageCacheHasNoGoroutine(t *testing.T) {
	before := runtime.NumGoroutine()
	_ = NotExists("goroutine-probe")
	after := runtime.NumGoroutine()
	if after > before {
		t.Fatalf("pkg/cache spawned goroutines: %d -> %d", before, after)
	}
}
