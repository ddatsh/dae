/*
 *  SPDX-License-Identifier: AGPL-3.0-only
 *  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

// Package leakdebug implements the weak-pointer live-object counters behind
// the /live diagnostics endpoint. Registries track objects of one type so a
// snapshot can report how many are still reachable after a forced GC — the
// cross-generation retention verdict for the reload path. Weak pointers never
// keep objects alive, so the counters cannot mask what they measure; a count
// only drops after a completed GC cycle.
package leakdebug

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"
	"sync"
	"weak"
)

// Enabled gates registration and diagnostics. It stays always-on so the /live
// endpoint works without special environment setup; weak-pointer tracking is
// negligible overhead.
var Enabled = true

// DumpGoroutinesNow writes a full goroutine dump to path on every call
// (no Once gate) — used by explicit diagnostics endpoints such as /live.
func DumpGoroutinesNow(path, reason string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fmt.Printf("[dae-trie-leak-debug] %s — dumping goroutines to %s\n", reason, path)
	return pprof.Lookup("goroutine").WriteTo(f, 2)
}

// Registry weakly tracks objects of one type. The zero value is ready to use.
type Registry[T any] struct {
	mu      sync.Mutex
	created int
	track   []trackEntry[T]
}

type trackEntry[T any] struct {
	site string
	ref  weak.Pointer[T]
}

// LiveObjects returns the tracked objects still reachable after a forced GC,
// in registration order (oldest first).
func (r *Registry[T]) LiveObjects() []*T {
	runtime.GC()
	r.mu.Lock()
	defer r.mu.Unlock()
	live := make([]*T, 0, len(r.track))
	for _, e := range r.track {
		if v := e.ref.Value(); v != nil {
			live = append(live, v)
		}
	}
	return live
}

// Register records v under the given site name. Objects that became
// unreachable but have not passed a GC yet still count as live in
// LiveObjects until the next collection completes.
func (r *Registry[T]) Register(v *T, name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.created++
	r.track = append(r.track, trackEntry[T]{site: name, ref: weak.Make(v)})
}
