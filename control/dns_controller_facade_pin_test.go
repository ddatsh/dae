/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"runtime"
	"testing"
	"time"
	"weak"

	"github.com/sirupsen/logrus"
)

// TestRetiredDnsFacadeNotPinnedByStoreGoroutines guards the store-sink
// invariant: the DNS cache janitor and the async BPF update worker are
// store-owned goroutines and must capture the shared *dnsControllerStore,
// never a generation facade. A facade captured by either goroutine stays
// pinned for the goroutine's lifetime — one ~32-byte DnsController per
// started goroutine, invisible to data-path leak scans, which is exactly
// the "dns_controller +1 per reload" signature the /live probe reports.
func TestRetiredDnsFacadeNotPinnedByStoreGoroutines(t *testing.T) {
	var (
		store *dnsControllerStore
		ref   weak.Pointer[DnsController]
	)
	// Construct and drop the facade inside a callee frame so this test
	// function's own stack slots never hold the pointer: Go does not clear
	// dead stack slots, so a stale slot would look like a pin and flake the
	// assertion below.
	func() {
		ctrl, err := NewDnsController(nil, &DnsControllerOption{Log: logrus.New()})
		if err != nil {
			t.Fatalf("NewDnsController: %v", err)
		}
		// Force-start the BPF worker next to the constructor-started janitor;
		// both goroutines must hold only the store.
		ctrl.startBpfUpdateWorker()
		store = ctrl.dnsControllerStore
		ref = weak.Make(ctrl)
	}()

	// The goroutines keep the store alive; the facade must not be.
	collected := false
	for i := 0; i < 100; i++ {
		runtime.GC()
		if ref.Value() == nil {
			collected = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !collected {
		t.Fatal("retired DnsController facade is still pinned: a store-owned goroutine captured the facade instead of the shared store")
	}

	// Stop the store-owned goroutines so the package goleak fence stays clean.
	if err := (&DnsController{dnsControllerStore: store}).Close(); err != nil {
		t.Fatalf("store teardown: %v", err)
	}
}
