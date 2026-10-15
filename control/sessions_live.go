/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"io"
	"net"
	"os"
	"runtime/debug"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/dae/component/daedns"
	dnspkg "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/pkg/leakdebug"
)

// facadeHeapDumpArmed/Once back the one-shot full-heap dump for the
// invisible-facade slow leak: the deep reflect scan cannot see closure
// capture environments (funcval payloads), which is the only remaining place
// a retired DnsController facade can hide. The dump freezes the world once
// and writes every heap object; the offline parser correlates the printed
// facade addresses with dump words to recover the reference chain.
var (
	facadeHeapDumpArmed atomic.Bool
	facadeHeapDumpOnce  sync.Once
)

// writeFacadeLeakHeapDump writes a full Go heap dump for offline analysis.
func writeFacadeLeakHeapDump() (string, error) {
	f, err := os.CreateTemp("", "dae-facade-leak-*.heap")
	if err != nil {
		return "", err
	}
	path := f.Name()
	defer f.Close()
	debug.WriteHeapDump(f.Fd())
	return path, nil
}

// Live-flow diagnostics for the /live debug endpoint.
//
// Established flows are owned by the process-level SessionManager and survive
// generation swaps: retirement never aborts established connections, so each
// flow keeps its retired generation (and its routing trie) alive until it ends
// or the relay idle watchdog reaps it. This snapshot reports every flow with
// the routing epoch it was established under, so post-reload retention can be
// inspected at runtime: flows whose epoch differs from the published active
// plane's epoch are exactly the graceful-drain survivors.

type LiveFlowInfo struct {
	Proto         string
	Epoch         routing.PolicyEpoch
	Retained      bool   // established under a non-active generation
	Client        string // LAN client address
	Target        string // immutable dial target selected at establishment
	SniffedDomain string // domain sniffed from the flow (TLS SNI / QUIC / HTTP), empty when none
	Outbound      string // outbound group name
	EgressAddr    string // resolved destination IP (original dst), not the proxy server address
}

func liveFlowRemoteAddr(c any) string {
	if ra, ok := c.(interface{ RemoteAddr() net.Addr }); ok {
		if addr := ra.RemoteAddr(); addr != nil {
			return addr.String()
		}
	}
	return ""
}

func (m *SessionManager) snapshotLiveFlows(activeEpoch routing.PolicyEpoch) []LiveFlowInfo {
	if m == nil {
		return nil
	}
	var flows []LiveFlowInfo
	m.flows.Range(func(_, v any) bool {
		f, ok := v.(*FlowRuntime)
		if !ok || f == nil {
			return true
		}
		info := LiveFlowInfo{
			Proto:         "tcp",
			Epoch:         f.binding.Route.PolicyEpoch,
			Retained:      f.binding.Route.PolicyEpoch != activeEpoch,
			Target:        f.binding.Egress.Target,
			SniffedDomain: f.binding.Egress.SniffedDomain,
		}
		if f.ingress != nil {
			info.Client = liveFlowRemoteAddr(f.ingress)
		}
		if f.binding.Egress.Outbound != nil {
			info.Outbound = f.binding.Egress.Outbound.Name
		}
		// The egress column reports the resolved destination IP — the address
		// the client's DNS lookup returned (the original BPF dst) — not the
		// proxy server address a proxied flow physically connects to. The
		// live conn's RemoteAddr is only a fallback for bindings adopted
		// before OrigDst existed.
		info.EgressAddr = f.binding.Egress.OrigDst
		flows = append(flows, info)
		return true
	})
	m.udpFlows.Range(func(_, v any) bool {
		f, ok := v.(*UDPFlowRuntime)
		if !ok || f == nil || f.endpoint == nil {
			return true
		}
		info := LiveFlowInfo{
			Proto:         "udp",
			Epoch:         f.binding.Route.PolicyEpoch,
			Retained:      f.binding.Route.PolicyEpoch != activeEpoch,
			Target:        f.binding.Egress.Target,
			SniffedDomain: f.binding.Egress.SniffedDomain,
		}
		if f.binding.Egress.Outbound != nil {
			info.Outbound = f.binding.Egress.Outbound.Name
		}
		info.Client = f.endpoint.poolKey.Src.String()
		if f.endpoint.poolKey.Dst.IsValid() {
			info.EgressAddr = f.endpoint.poolKey.Dst.String()
		}
		flows = append(flows, info)
		return true
	})
	sort.Slice(flows, func(i, j int) bool {
		if flows[i].Epoch != flows[j].Epoch {
			return flows[i].Epoch < flows[j].Epoch
		}
		if flows[i].Proto != flows[j].Proto {
			return flows[i].Proto == "tcp" // TCP rows above UDP rows
		}
		return flows[i].Client < flows[j].Client
	})
	return flows
}

// WriteLiveFlows writes the established-flow listing served by the /live
// debug endpoint. Flows marked "*retained" were established under a routing
// epoch that is no longer active — the graceful-drain survivors that keep a
// retired generation (and its routing tries) pinned until they end.
func WriteLiveFlows(w io.Writer) {
	active := activeControlPlanePublication.plane.Load()
	if active == nil {
		fmt.Fprintln(w, "no active control plane published yet")
		return
	}
	activeEpoch := active.PolicyEpoch()
	flows := active.sessionManager.snapshotLiveFlows(activeEpoch)
	retained := 0
	for _, f := range flows {
		if f.Retained {
			retained++
		}
	}
	fmt.Fprintf(w, "active epoch %d; %d established flows (%d retired-generation survivors marked *retired)\n\n",
		activeEpoch, len(flows), retained)
	probeAnomalous := false
	var planes []*ControlPlane
	if leakdebug.Enabled {
		// Live-object probes (forced GC): a plane/routing_matcher/router/dns
		// count above 1 means a retired generation is still pinned by
		// something other than the flows listed below.
		liveControllers := dnsControllerLeakRegistry.LiveObjects()
		planes = planeLeakRegistry.LiveObjects()
		counts := struct {
			plane, matcher, router, dns, controller, store, listener int
		}{
			len(planes),
			len(routingMatcherLeakRegistry.LiveObjects()),
			daedns.LeakLiveRouters(),
			dnspkg.LeakLiveDns(),
			len(liveControllers),
			len(dnsStoreLeakRegistry.LiveObjects()),
			len(dnsListenerLeakRegistry.LiveObjects()),
		}
		fmt.Fprintf(w, "probe live: plane=%d routing_matcher=%d dns_router=%d dns=%d dns_controller=%d dns_store=%d dns_listener=%d\n\n",
			counts.plane, counts.matcher, counts.router, counts.dns, counts.controller, counts.store, counts.listener)
		// TCP relays are owned by the retired plane's serve goroutines, so
		// retained TCP flows keep one extra plane (and its routing matcher,
		// router, and dns) alive by design. Retained UDP endpoints live in
		// the process-level session manager and pin nothing. Controllers are
		// checked against the exact per-generation expectation below. Any
		// live count beyond expectation is unexplained and worth a deep scan.
		tcpRetained := 0
		for _, f := range flows {
			if f.Retained && f.Proto == "tcp" {
				tcpRetained++
			}
		}
		expectedGens := 1
		if tcpRetained > 0 {
			expectedGens = 2
		}
		// Exact controller expectation: every live plane holds its own
		// generation facade. The store-owned background goroutines (DNS cache
		// janitor, async BPF update worker) run on *dnsControllerStore
		// receivers and capture the shared store, never a facade, so they add
		// nothing. One overshoot slot absorbs a transient: an in-flight DNS
		// query that dispatched through a facade right before the reload
		// handoff can briefly outlive its plane (UDP flows do not retain
		// their plane) and pin that facade for the query duration.
		expectedControllers := counts.plane + 1
		probeAnomalous = counts.plane > expectedGens || counts.matcher > expectedGens ||
			counts.router > expectedGens || counts.dns > expectedGens ||
			counts.controller > expectedControllers || counts.store > 1
		if counts.controller > expectedControllers {
			// Invisible-facade slow leak signature. Publish the live facade
			// addresses so the offline heap-dump parser can correlate them,
			// and arm the one-shot dump fired below.
			facadeHeapDumpArmed.Store(true)
			fmt.Fprintf(w, "live dns controllers:")
			for _, c := range liveControllers {
				fmt.Fprintf(w, " %p", c)
			}
			fmt.Fprintln(w)
		}
	}
	if probeAnomalous {
		// A retired generation is still reachable while no flow explains it:
		// walk the live graph for the data-field path that holds it.
		if len(planes) >= 2 {
			runLeakDeepScan(w, planes[0], planes[1:])
		} else {
			runLeakDeepScan(w, nil, nil)
		}
		fmt.Fprintln(w)
		if facadeHeapDumpArmed.Load() {
			facadeHeapDumpOnce.Do(func() {
				path, err := writeFacadeLeakHeapDump()
				if err != nil {
					fmt.Fprintf(w, "facade leak heap dump failed: %v\n", err)
					return
				}
				fmt.Fprintf(w, "facade leak heap dump written to %s (send it back for offline reference-chain analysis)\n", path)
			})
		}
	}
	if len(flows) == 0 {
		fmt.Fprintln(w, "(no established flows)")
		return
	}
	// Dynamic column widths: domains and IPv6 addresses have unbounded length,
	// so fixed padding misaligns the table exactly when it is most useful.
	// The retained marker lives in its own early column and can never be
	// pushed around by a long target.
	const (
		colEpoch = iota
		colGen
		colProto
		colClient
		colTarget
		colOutbound
		colEgress
		colCount
	)
	header := [colCount]string{"epoch", "gen", "proto", "client", "target", "outbound", "egress"}
	rows := make([][colCount]string, len(flows))
	for i, f := range flows {
		gen := "active"
		if f.Retained {
			gen = "*retired"
		}
		// Prefer the sniffed domain so the table reads as "who talks to what
		// site"; flows with no sniffed domain (plain IP traffic) fall back to
		// the dial target.
		targetCell := f.Target
		if f.SniffedDomain != "" {
			targetCell = f.SniffedDomain
		}
		rows[i] = [colCount]string{
			strconv.FormatUint(uint64(f.Epoch), 10),
			gen,
			f.Proto,
			f.Client,
			targetCell,
			f.Outbound,
			f.EgressAddr,
		}
	}
	widths := [colCount]int{}
	for i, h := range header {
		widths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}
	printRow := func(cells [colCount]string) {
		for i, cell := range cells {
			if i == len(cells)-1 {
				fmt.Fprintln(w, cell)
			} else {
				fmt.Fprintf(w, "%-*s  ", widths[i], cell)
			}
		}
	}
	printRow(header)
	for _, row := range rows {
		printRow(row)
	}
}
