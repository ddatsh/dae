/*
 *  SPDX-License-Identifier: AGPL-3.0-only
 *  Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"sync"
	"unsafe"

	"github.com/daeuniverse/dae/component/daedns"
	dnspkg "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/pkg/leakdebug"
)

// Temporary reload-leak diagnostics: reflect-based reference-graph scan.
//
// scanForLeakRefs walks the object graph reachable from the given roots and
// reports every field path that stores a pointer to a scan target. Targets are
// any object that should have been garbage-collected after a reload: retired
// control planes, stale daedns.Router holders of DNS tries, and stale dns.Dns
// instances. It covers all data edges (struct fields, slices, maps,
// interfaces, arrays, atomic.Pointer payloads); function-value closures are
// NOT introspectable via reflect and remain a documented blind spot — the
// prepared-DNS hook probes cover the closure slots known to capture a plane.

var (
	leakScanRootsMu sync.Mutex
	leakScanRoots   []func() []any
)

// RegisterLeakScanRoots installs a callback supplying extra graph roots
// (cmd-level long-lived structures) for the deep reference scan.
func RegisterLeakScanRoots(f func() []any) {
	if !leakdebug.Enabled {
		return
	}
	leakScanRootsMu.Lock()
	leakScanRoots = append(leakScanRoots, f)
	leakScanRootsMu.Unlock()
}

type leakScanTarget struct {
	name string
	typ  reflect.Type
	ptr  uintptr
}

type leakScanState struct {
	targets []leakScanTarget
	visited map[uintptr]struct{}
	paths   []string
	nodes   int
}

const (
	leakScanMaxDepth = 24
	leakScanMaxNodes = 1 << 21
)

// leakScanSkipTypes are subtree-heavy types whose interiors cannot hold a
// plane pointer; skipping them keeps the scan inside the node budget.
var leakScanSkipTypes = map[reflect.Type]struct{}{}

func scanForLeakRefs(rootName string, root any, state *leakScanState) {
	if len(state.targets) == 0 {
		return
	}
	v := reflect.ValueOf(root)
	state.walk(rootName, v, 0)
}

func (s *leakScanState) match(v reflect.Value, ptr uintptr) (leakScanTarget, bool) {
	for _, tgt := range s.targets {
		if v.Type() == tgt.typ && ptr == tgt.ptr {
			return tgt, true
		}
	}
	return leakScanTarget{}, false
}

var unsafePointerType = reflect.TypeOf(unsafe.Pointer(nil))

// atomicPointerPayload recognizes the reflect shape of atomic.Pointer[T] /
// weak.Pointer[T]: a struct whose only pointer-sized field is an
// unsafe.Pointer payload and whose remaining fields are zero-size markers
// (at least one [0]*T type-parameter witness). It returns the payload as a
// *T reflect.Value so the walk can follow atomic hops.
func atomicPointerPayload(v reflect.Value) (reflect.Value, bool) {
	t := v.Type()
	if t.Kind() != reflect.Struct || t.NumField() == 0 || t.NumField() > 4 {
		return reflect.Value{}, false
	}
	payloadField, elem := -1, reflect.Type(nil)
	for i := 0; i < t.NumField(); i++ {
		ft := t.Field(i).Type
		switch {
		case ft == unsafePointerType:
			if payloadField >= 0 {
				return reflect.Value{}, false // not the single-payload shape
			}
			payloadField = i
		case ft.Kind() == reflect.Array && ft.Len() == 0 && ft.Elem().Kind() == reflect.Ptr:
			elem = ft.Elem().Elem() // [0]*T -> *T -> T
		case ft.Size() == 0:
			// zero-size marker (noCopy and friends)
		default:
			return reflect.Value{}, false
		}
	}
	if payloadField < 0 || elem == nil || v.Field(payloadField).IsNil() {
		return reflect.Value{}, false
	}
	// NewAt bypasses the read-only flag of the unexported field; the walk
	// only reads kind/pointer values and never writes through the result.
	return reflect.NewAt(elem, v.Field(payloadField).UnsafePointer()).Elem(), true
}

func (s *leakScanState) walk(path string, v reflect.Value, depth int) {
	if depth > leakScanMaxDepth || s.nodes > leakScanMaxNodes {
		return
	}
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return
		}
		s.walk(path, v.Elem(), depth+1)
	case reflect.Ptr:
		if v.IsNil() {
			return
		}
		ptr := v.Pointer()
		if tgt, ok := s.match(v, uintptr(ptr)); ok {
			s.paths = append(s.paths, tgt.name+" <- "+path)
			return
		}
		if _, done := s.visited[uintptr(ptr)]; done {
			return
		}
		s.visited[uintptr(ptr)] = struct{}{}
		s.nodes++
		s.walk(path, v.Elem(), depth+1)
	case reflect.Struct:
		t := v.Type()
		if _, skip := leakScanSkipTypes[t]; skip {
			return
		}
		s.nodes++
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if payload, ok := atomicPointerPayload(v.Field(i)); ok {
				// atomic.Pointer[T]/weak.Pointer[T]: the payload lives behind
				// a lone unsafe.Pointer field. Compare it against the targets
				// and FOLLOW it — sync.Map.read, controller runtimeState, and
				// pool entries are invisible to the walk without this hop.
				s.walk(path+"."+f.Name, payload, depth+1)
				continue
			}
			s.walk(path+"."+f.Name, v.Field(i), depth+1)
		}
	case reflect.Slice:
		if v.IsNil() || v.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		s.nodes++
		n := v.Len()
		if n > 4096 {
			n = 4096 // bounded sampling for very large slices
		}
		for i := 0; i < n; i++ {
			s.walk(fmt.Sprintf("%s[%d]", path, i), v.Index(i), depth+1)
		}
	case reflect.Array:
		s.nodes++
		n := v.Len()
		if n > 4096 {
			n = 4096
		}
		for i := 0; i < n; i++ {
			s.walk(fmt.Sprintf("%s[%d]", path, i), v.Index(i), depth+1)
		}
	case reflect.Map:
		if v.IsNil() {
			return
		}
		s.nodes++
		iter := v.MapRange()
		count := 0
		for iter.Next() && count < 4096 {
			count++
			s.walk(fmt.Sprintf("%s[%v]", path, iter.Key()), iter.Value(), depth+1)
		}
	case reflect.UnsafePointer:
		// atomic.Pointer[T] stores its payload as an UnsafePointer field;
		// without this case every atomic slot would be invisible to the scan.
		for _, tgt := range s.targets {
			if uintptr(v.UnsafePointer()) == tgt.ptr {
				s.paths = append(s.paths, tgt.name+" <- "+path+" (atomic/unsafe)")
			}
		}
	default:
		// Chans, funcs, primitives: nothing introspectable.
	}
}

// leakScanCollectTargets builds the scan targets: the retired plane, plus
// every live daedns.Router / dns.Dns except the newest of each (the active
// generation's, created last). Objects created earlier that are still alive
// are stale holders of tries and must be explained by the scan. Active planes
// are roots, never targets.
func leakScanCollectTargets(retired *ControlPlane) []leakScanTarget {
	var targets []leakScanTarget
	if retired != nil {
		targets = append(targets, leakScanTarget{
			name: fmt.Sprintf("retiredPlane{%p}", retired),
			typ:  reflect.TypeOf(retired),
			ptr:  uintptr(unsafe.Pointer(retired)),
		})
	}
	var staleRouters []*daedns.Router
	if routers := daedns.LeakLiveRouterPointers(); len(routers) > 1 {
		staleRouters = routers[:len(routers)-1]
		for _, r := range staleRouters {
			if r == nil {
				continue
			}
			targets = append(targets, leakScanTarget{
				name: fmt.Sprintf("staleRouter{%p}", r),
				typ:  reflect.TypeOf(r),
				ptr:  uintptr(unsafe.Pointer(r)),
			})
		}
	}
	// A generation-scoped resolver wrapper that still references a stale
	// router is itself a pin (its atomic.Pointer payload is visible to the
	// UnsafePointer walk); targeting it lets the scan find whoever holds the
	// wrapper, one hop below the router.
	for _, dv := range daedns.LeakResolvingDialers() {
		r := daedns.LeakHeldRouter(dv)
		if r == nil {
			continue
		}
		stale := false
		for _, sr := range staleRouters {
			if sr == r {
				stale = true
				break
			}
		}
		if !stale {
			continue
		}
		targets = append(targets, leakScanTarget{
			name: fmt.Sprintf("staleResolvingDialer{%p} (holds staleRouter{%p})", dv, r),
			typ:  reflect.TypeOf(dv),
			ptr:  reflect.ValueOf(dv).Pointer(),
		})
	}
	if dnses := dnspkg.LeakLiveDnsPointers(); len(dnses) > 1 {
		for _, d := range dnses[:len(dnses)-1] {
			if d == nil {
				continue
			}
			targets = append(targets, leakScanTarget{
				name: fmt.Sprintf("staleDns{%p}", d),
				typ:  reflect.TypeOf(d),
				ptr:  uintptr(unsafe.Pointer(d)),
			})
		}
	}
	// Facades are deliberately NOT scan targets: every live plane legitimately
	// holds its own generation facade (controller count = 1 store owner +
	// live planes), and the drain-retained planes keep theirs while flowing.
	return targets
}

// leakScanCollectRoots gathers everything whose subtree may hold a stale
// object: the active planes, the shared DNS layer (facades, stores,
// controllers) that survives generations, and cmd-level long-lived structures.
func leakScanCollectRoots(activePlanes []*ControlPlane) []leakScanRoot {
	var roots []leakScanRoot
	for _, p := range activePlanes {
		if p == nil {
			continue
		}
		roots = append(roots, leakScanRoot{
			name: fmt.Sprintf("activePlane{%p}", p),
			obj:  p,
		})
	}
	for _, c := range dnsControllerLeakRegistry.LiveObjects() {
		roots = append(roots, leakScanRoot{
			name: fmt.Sprintf("dnsController{%p}", c),
			obj:  c,
		})
	}
	for _, s := range dnsStoreLeakRegistry.LiveObjects() {
		roots = append(roots, leakScanRoot{
			name: fmt.Sprintf("dnsStore{%p}", s),
			obj:  s,
		})
	}
	// Process-global pools survive generations and hold the retained UDP
	// endpoints (whose transport chains may still reference a retired
	// generation's dialer wrappers).
	roots = append(roots,
		leakScanRoot{name: "DefaultUdpEndpointPool", obj: DefaultUdpEndpointPool},
		leakScanRoot{name: "DefaultAnyfromPool", obj: DefaultAnyfromPool},
	)
	leakScanRootsMu.Lock()
	rootFns := append([]func() []any(nil), leakScanRoots...)
	leakScanRootsMu.Unlock()
	for _, fn := range rootFns {
		for _, root := range fn() {
			if root == nil {
				continue
			}
			roots = append(roots, leakScanRoot{
				name: fmt.Sprintf("cmdRoot{%T}", root),
				obj:  root,
			})
		}
	}
	return roots
}

type leakScanRoot struct {
	name string
	obj  any
}

// runLeakDeepScan reports every data-field path from the scan roots that still
// points at a scan target. Intended for the final delayed snapshot and the
// /live diagnostics endpoint. A nil writer defaults to stdout.
func runLeakDeepScan(w io.Writer, retired *ControlPlane, activePlanes []*ControlPlane) {
	if !leakdebug.Enabled {
		return
	}
	if w == nil {
		w = os.Stdout
	}
	targets := leakScanCollectTargets(retired)
	if len(targets) == 0 {
		fmt.Fprintln(w, "deep scan: no stale scan targets (nothing should have been retained)")
		return
	}
	state := &leakScanState{
		targets: targets,
		visited: map[uintptr]struct{}{},
	}
	for _, root := range leakScanCollectRoots(activePlanes) {
		// A root that is itself a scan target (e.g. a stale facade listed as
		// both root and target) would self-match on entry; skip it — walking
		// its own subtree says nothing about who holds it.
		rv := reflect.ValueOf(root.obj)
		if rv.Kind() == reflect.Ptr && !rv.IsNil() {
			if _, hit := state.match(rv, rv.Pointer()); hit {
				continue
			}
		}
		scanForLeakRefs(root.name, root.obj, state)
	}
	if len(state.paths) == 0 {
		fmt.Fprintf(w, "deep scan: no data-field reference to %d stale target(s) (nodes=%d; closures not visible to reflect)\n",
			len(targets), state.nodes)
		for _, tgt := range targets {
			fmt.Fprintf(w, "  stale target: %s (%s)\n", tgt.name, tgt.typ)
		}
		// With no data edge from any root, the holder is a func closure or an
		// object outside the rooted set — a goroutine dump names parked
		// closure holders directly.
		dumpPath := "/tmp/dae_stale_holder_dump.txt"
		if err := leakdebug.DumpGoroutinesNow(dumpPath, fmt.Sprintf("deep scan missed %d stale target(s)", len(targets))); err == nil {
			fmt.Fprintf(w, "  goroutine dump written to %s (send it back for closure-holder analysis)\n", dumpPath)
		}
		return
	}
	fmt.Fprintf(w, "deep scan: %d retention path(s) found (nodes=%d)\n", len(state.paths), state.nodes)
	for _, p := range state.paths {
		fmt.Fprintf(w, "  deep scan PIN: %s\n", p)
	}
}
