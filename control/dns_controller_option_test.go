/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"
)

// dnsControllerOption is called from three places: the initial build, reload
// reuse (ReuseForReload) and the staged DNS handoff. Every config-derived
// tunable must ride along on all of them — a field that is only patched onto
// the option at the build call site silently resets to its zero value on
// reload, which previously turned the DNS cache size limit off.
func TestDnsControllerOptionCarriesRuntimeTunables(t *testing.T) {
	fixedTtl := map[string]int{"example.com.": 60}
	plane := &ControlPlane{
		controlPlaneDNSRuntime: controlPlaneDNSRuntime{
			dnsFixedDomainTtl:     fixedTtl,
			dnsOptimisticCache:    true,
			dnsOptimisticCacheTtl: 600,
			dnsMaxCacheSize:       65536,
			dnsIpVersionPrefer:    4,
		},
	}

	option := plane.dnsControllerOption()
	if option == nil {
		t.Fatal("dnsControllerOption() = nil")
		return
	}

	for _, tc := range []struct {
		field string
		got   any
		want  any
	}{
		{field: "OptimisticCache", got: option.OptimisticCache, want: true},
		{field: "OptimisticCacheTtl", got: option.OptimisticCacheTtl, want: 600},
		{field: "MaxCacheSize", got: option.MaxCacheSize, want: 65536},
		{field: "IpVersionPrefer", got: option.IpVersionPrefer, want: 4},
	} {
		t.Run(tc.field, func(t *testing.T) {
			if tc.got != tc.want {
				t.Fatalf("dnsControllerOption().%s = %v, want %v", tc.field, tc.got, tc.want)
			}
		})
	}
	if len(option.FixedDomainTtl) != 1 || option.FixedDomainTtl["example.com."] != 60 {
		t.Fatalf("dnsControllerOption().FixedDomainTtl = %v, want %v", option.FixedDomainTtl, fixedTtl)
	}
}

// The prepared-DNS hooks close over the previous control-plane generation, so
// every terminal path of startPreparedDNSListenerWithWarmupTimeout must drop
// them. Previously the full-handoff path (reuse hook reuses the listener,
// flipping delayDNSListenerStart off) returned early and left the start hook
// set forever, pinning the retired generation on the active plane.
func TestPreparedDNSHooksClearedOnTerminalPaths(t *testing.T) {
	t.Run("full handoff via reuse hook", func(t *testing.T) {
		rt := newControlPlaneDNSRuntime(true)
		rt.noteDNSUpstreamAvailable()
		startHookRan := false
		rt.preparedDNSReuseHook = func() error {
			// Mirror reuseDNSListenerFrom: a successful listener reuse marks
			// the prepared flow complete.
			rt.delayDNSListenerStart = false
			return nil
		}
		rt.preparedDNSStartHook = func() error {
			startHookRan = true
			return nil
		}
		if err := rt.startPreparedDNSListenerWithWarmupTimeout(t.Context(), nil, nil, time.Second); err != nil {
			t.Fatalf("startPreparedDNSListenerWithWarmupTimeout: %v", err)
		}
		if startHookRan {
			t.Fatal("start hook ran after full listener handoff")
		}
		if rt.preparedDNSReuseHook != nil || rt.preparedDNSStartHook != nil {
			t.Fatal("hooks survive the full-handoff early return; retired generation stays pinned")
		}
	})

	t.Run("already started at entry", func(t *testing.T) {
		rt := newControlPlaneDNSRuntime(false)
		reuseHookRan := false
		rt.preparedDNSReuseHook = func() error {
			reuseHookRan = true
			return nil
		}
		rt.preparedDNSStartHook = func() error { return nil }
		if err := rt.startPreparedDNSListenerWithWarmupTimeout(t.Context(), nil, nil, time.Second); err != nil {
			t.Fatalf("startPreparedDNSListenerWithWarmupTimeout: %v", err)
		}
		if reuseHookRan {
			t.Fatal("reuse hook ran although the listener was already started")
		}
		if rt.preparedDNSReuseHook != nil || rt.preparedDNSStartHook != nil {
			t.Fatal("hooks survive the entry early return; retired generation stays pinned")
		}
	})
}
