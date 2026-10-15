/*
 *  SPDX-License-Identifier: AGPL-3.0-only
 *  Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"github.com/daeuniverse/dae/pkg/leakdebug"
)

// Weak-pointer registries backing the /live diagnostics endpoint (main.go)
// and the reference-graph deep scan (leakscan.go). Registration is cheap:
// weak pointers never keep objects alive. Live counts are the cross-generation
// retention verdict for the reload path — expected values are documented in
// sessions_live.go.
var (
	// Layered probes for the DNS-handoff retention scenario: they separate a
	// direct pin on the plane from a pin routed through the DNS facade, the
	// shared store, or the listener (whose controller field holds the plane).
	planeLeakRegistry          leakdebug.Registry[ControlPlane]
	routingMatcherLeakRegistry leakdebug.Registry[RoutingMatcher]
	dnsControllerLeakRegistry  leakdebug.Registry[DnsController]
	dnsStoreLeakRegistry       leakdebug.Registry[dnsControllerStore]
	dnsListenerLeakRegistry    leakdebug.Registry[DNSListener]
)
