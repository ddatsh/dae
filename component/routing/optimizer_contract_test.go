/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/geodata"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

func TestSharedParams(t *testing.T) {
	p0 := &config_parser.Param{Key: "k0", Val: "v0"}

	// Exact-capacity slices are returned as-is (zero copy).
	exact := make([]*config_parser.Param, 1)
	exact[0] = p0
	if got := sharedParams(exact); cap(got) != 1 || got[0] != p0 {
		t.Fatalf("exact slice should be shared, got cap=%d", cap(got))
	}

	// Spare capacity is compacted once, so stray appends cannot reach shared
	// cache entries.
	spare := make([]*config_parser.Param, 1, 4)
	spare[0] = p0
	frozen := sharedParams(spare)
	if cap(frozen) != 1 {
		t.Fatalf("expected cap 1, got %d", cap(frozen))
	}
	if frozen[0] != p0 {
		t.Fatalf("expected shared param pointer")
	}

	if sharedParams(nil) != nil {
		t.Fatalf("empty slice should canonicalize to nil")
	}
}

func TestPostDatReaderOptimizersDoNotMutateCachedParams(t *testing.T) {
	originKey := string(consts.RoutingDomainKey_Suffix)
	originVal := "example.com"
	// Cache hits hand out the SAME backing array (zero-copy contract).
	cached := []*config_parser.Param{
		{Key: originKey, Val: originVal},
	}
	hit1 := cached
	hit2 := cached

	// DatReaderOptimizer builds a freshly allocated merged Params slice for
	// each rule; it never installs the cached backing array as f.Params.
	rule1Params := make([]*config_parser.Param, 0, len(hit1)+1)
	rule1Params = append(rule1Params, hit1...)
	rule1Params = append(rule1Params, &config_parser.Param{Key: string(consts.RoutingDomainKey_Keyword), Val: "example"})
	rule2Params := make([]*config_parser.Param, 0, len(hit2))
	rule2Params = append(rule2Params, hit2...)

	rules := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{
				{
					Name:   consts.Function_Domain,
					Params: rule1Params,
				},
			},
			Outbound: config_parser.Function{Name: "out"},
		},
		{
			AndFunctions: []*config_parser.Function{
				{
					Name:   consts.Function_Domain,
					Params: rule2Params,
				},
			},
			Outbound: config_parser.Function{Name: "out"},
		},
	}

	var err error
	rules, err = (&MergeAndSortRulesOptimizer{}).Optimize(rules)
	if err != nil {
		t.Fatalf("MergeAndSortRulesOptimizer failed: %v", err)
	}
	_, err = (&DeduplicateParamsOptimizer{}).Optimize(rules)
	if err != nil {
		t.Fatalf("DeduplicateParamsOptimizer failed: %v", err)
	}

	if len(cached) != 1 || cached[0].Key != originKey || cached[0].Val != originVal {
		t.Fatalf("cached slice mutated: %+v", cached)
	}
}

// TestDatReaderGeoSiteCacheZeroCopy drives the full DatReader -> MergeAndSort
// -> Deduplicate pipeline against a real geosite.dat. Two rules expand the
// same geosite code, so every expansion after the first is a cache hit that
// must share the cached backing array, and the later in-place merge/sort must
// not reorder or corrupt the cached slice.
func TestDatReaderGeoSiteCacheZeroCopy(t *testing.T) {
	// File order intentionally differs from key/value sort order:
	// suffix:b.com, full:a.example, keyword:c
	// sorts to: full, keyword, suffix.
	list := &geodata.GeoSiteList{Entry: []*geodata.GeoSite{{
		CountryCode: "cn",
		Domain: []*geodata.Domain{
			{Type: geodata.Domain_RootDomain, Value: "b.com"},
			{Type: geodata.Domain_Full, Value: "a.example"},
			{Type: geodata.Domain_Plain, Value: "c"},
		},
	}}}
	raw, err := proto.Marshal(list)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "geosite.dat"), raw, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	log := logrus.New()
	log.SetOutput(io.Discard)
	reader := &DatReaderOptimizer{Logger: log, LocationFinder: assets.NewLocationFinder([]string{dir})}

	first, err := reader.loadGeoSite("geosite", "cn")
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	second, err := reader.loadGeoSite("geosite", "cn")
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if len(first) != 3 || cap(first) != 3 {
		t.Fatalf("unexpected first slice len=%d cap=%d", len(first), cap(first))
	}
	if &first[0] != &second[0] {
		t.Fatalf("cache hit must share the cached backing array")
	}

	// Expand two identical singleton rules through DatReaderOptimizer.
	rules := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{{
				Name:   consts.Function_Domain,
				Params: []*config_parser.Param{{Key: "geosite", Val: "cn"}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		},
		{
			AndFunctions: []*config_parser.Function{{
				Name:   consts.Function_Domain,
				Params: []*config_parser.Param{{Key: "geosite", Val: "cn"}},
			}},
			Outbound: config_parser.Function{Name: "proxy"},
		},
	}
	rules, err = reader.Optimize(rules)
	if err != nil {
		t.Fatalf("DatReader Optimize: %v", err)
	}
	rules, err = (&MergeAndSortRulesOptimizer{}).Optimize(rules)
	if err != nil {
		t.Fatalf("MergeAndSort: %v", err)
	}
	rules, err = (&DeduplicateParamsOptimizer{}).Optimize(rules)
	if err != nil {
		t.Fatalf("Deduplicate: %v", err)
	}

	// The two identical singletons merge and dedup to the 3 unique params.
	if len(rules) != 1 || len(rules[0].AndFunctions[0].Params) != 3 {
		t.Fatalf("unexpected rules after pipeline: %+v", rules[0].AndFunctions)
	}
	sorted := rules[0].AndFunctions[0].Params
	wantSorted := []struct{ key, val string }{
		{string(consts.RoutingDomainKey_Full), "a.example"},
		{string(consts.RoutingDomainKey_Keyword), "c"},
		{string(consts.RoutingDomainKey_Suffix), "b.com"},
	}
	for i, w := range wantSorted {
		if sorted[i].Key != w.key || sorted[i].Val != w.val {
			t.Fatalf("sorted[%d] = %q:%q, want %q:%q", i, sorted[i].Key, sorted[i].Val, w.key, w.val)
		}
	}

	// The cached slice must keep its original (file) order and contents.
	cached := reader.geoSiteCache["geosite.dat:cn"]
	wantCached := []struct{ key, val string }{
		{string(consts.RoutingDomainKey_Suffix), "b.com"},
		{string(consts.RoutingDomainKey_Full), "a.example"},
		{string(consts.RoutingDomainKey_Keyword), "c"},
	}
	if len(cached) != len(wantCached) {
		t.Fatalf("cached len = %d, want %d", len(cached), len(wantCached))
	}
	for i, w := range wantCached {
		if cached[i].Key != w.key || cached[i].Val != w.val {
			t.Fatalf("cached[%d] = %q:%q, want %q:%q", i, cached[i].Key, cached[i].Val, w.key, w.val)
		}
		if cached[i] != first[i] {
			t.Fatalf("cached[%d] pointer changed", i)
		}
	}
}

// TestMergeAndSortRulesOptimizerMergesPositiveSingletons verifies that two
// positive singleton rules with the same outbound are merged into one.
func TestMergeAndSortRulesOptimizerMergesPositiveSingletons(t *testing.T) {
	rules := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{
				{Name: consts.Function_Domain, Params: []*config_parser.Param{{Key: string(consts.RoutingDomainKey_Suffix), Val: "a.com"}}},
			},
			Outbound: config_parser.Function{Name: "proxy"},
		},
		{
			AndFunctions: []*config_parser.Function{
				{Name: consts.Function_Domain, Params: []*config_parser.Param{{Key: string(consts.RoutingDomainKey_Suffix), Val: "b.com"}}},
			},
			Outbound: config_parser.Function{Name: "proxy"},
		},
	}

	out, err := (&MergeAndSortRulesOptimizer{}).Optimize(rules)
	if err != nil {
		t.Fatalf("Optimize failed: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 merged rule, got %d", len(out))
	}
	if got := len(out[0].AndFunctions[0].Params); got != 2 {
		t.Fatalf("expected 2 params after merge, got %d", got)
	}
}

// TestMergeAndSortRulesOptimizerDoesNotMergeInvertedSingletons ensures that
// inverted (!) singleton rules are NOT merged, because De Morgan's law makes
// !f(a)->X OR !f(b)->X inequivalent to !f(a,b)->X. Regression test for the
// optimizer correctness bug surfaced in the routing review.
func TestMergeAndSortRulesOptimizerDoesNotMergeInvertedSingletons(t *testing.T) {
	rules := []*config_parser.RoutingRule{
		{
			AndFunctions: []*config_parser.Function{
				{Name: consts.Function_Domain, Not: true, Params: []*config_parser.Param{{Key: string(consts.RoutingDomainKey_Suffix), Val: "a.com"}}},
			},
			Outbound: config_parser.Function{Name: "proxy"},
		},
		{
			AndFunctions: []*config_parser.Function{
				{Name: consts.Function_Domain, Not: true, Params: []*config_parser.Param{{Key: string(consts.RoutingDomainKey_Suffix), Val: "b.com"}}},
			},
			Outbound: config_parser.Function{Name: "proxy"},
		},
	}

	out, err := (&MergeAndSortRulesOptimizer{}).Optimize(rules)
	if err != nil {
		t.Fatalf("Optimize failed: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("inverted singletons must NOT be merged: expected 2 rules, got %d", len(out))
	}
	for i, r := range out {
		if len(r.AndFunctions) != 1 || len(r.AndFunctions[0].Params) != 1 {
			t.Fatalf("rule %d: expected single inverted singleton, got AndFunctions=%v", i, r.AndFunctions)
		}
		if !r.AndFunctions[0].Not {
			t.Fatalf("rule %d: expected Not=true preserved", i)
		}
	}
}
