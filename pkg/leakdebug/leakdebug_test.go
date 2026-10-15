/*
 *  SPDX-License-Identifier: AGPL-3.0-only
 *  Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package leakdebug

import (
	"runtime"
	"testing"
)

// liveObjects must report exactly the objects that are still strongly
// reachable: a dropped object clears after a GC, a held object never does.
// The reload-leak verdicts (plane_live etc.) rest on this invariant.
func TestRegistryWeakSemantics(t *testing.T) {
	// Register is a no-op unless the probe is enabled; the tests run without
	// DAE_TRIE_LEAK_DEBUG set, so flip it explicitly and restore afterwards.
	prev := Enabled
	Enabled = true
	defer func() { Enabled = prev }()

	var reg Registry[int]
	held := new(int)
	reg.Register(held, "held")
	registerDropped(&reg)

	// LiveObjects forces a GC, but the Go GC does not zero dead stack slots
	// or registers: a dropped object may stay reachable through a stale copy
	// for one collection (the same artifact that makes the first
	// post-retirement plane_live snapshot read 2). Re-probe until it settles.
	live := reg.LiveObjects()
	for i := 0; len(live) != 1 && i < 3; i++ {
		live = reg.LiveObjects()
	}
	if len(live) != 1 || live[0] != held {
		t.Fatalf("LiveObjects() before drop = %d entries, want exactly the held object", len(live))
	}

	runtime.GC()
	live = reg.LiveObjects()
	if len(live) != 1 || live[0] != held {
		t.Fatalf("LiveObjects() after GC = %d entries, want exactly the held object", len(live))
	}
	// The held variable's last use is this comparison; without KeepAlive the
	// liveness analysis may end its stack slot before LiveObjects runs, making
	// the sole reference unreachable and the weak pointer clear.
	runtime.KeepAlive(held)
}

// registerDropped allocates and registers the dropped object in a callee
// frame so no copy of the pointer survives into the test frame.
func registerDropped(r *Registry[int]) {
	r.Register(new(int), "dropped")
}
