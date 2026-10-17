/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"fmt"
	"net/netip"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/geodata"
	"github.com/mohae/deepcopy"
	"github.com/sirupsen/logrus"
)

type RulesOptimizer interface {
	Optimize(rules []*config_parser.RoutingRule) ([]*config_parser.RoutingRule, error)
}

func DeepCloneRules(rules []*config_parser.RoutingRule) (newRules []*config_parser.RoutingRule) {
	if rules == nil {
		return nil
	}
	return deepcopy.Copy(rules).([]*config_parser.RoutingRule)
}

func ApplyRulesOptimizers(rules []*config_parser.RoutingRule, optimizers ...RulesOptimizer) ([]*config_parser.RoutingRule, error) {
	restoreGC := WithRelaxedGC()
	defer restoreGC()
	rules = DeepCloneRules(rules)
	var err error
	for _, opt := range optimizers {
		if rules, err = opt.Optimize(rules); err != nil {
			return nil, err
		}
	}
	return rules, err
}

// heavyBuildGCPercent temporarily lowers GC frequency while geosite/geoip
// data sets are expanded and routing matchers are built. Those phases
// allocate tens of millions of pointers; with the default GOGC (100) the
// concurrent marker runs almost continuously and write-barrier flushing plus
// goroutine suspension dominate CPU. 400 cuts GC frequency by ~4x while still
// bounding heap growth; GOMEMLIMIT (set from the cgroup ceiling elsewhere)
// stays in force as a hard safety net.
const heavyBuildGCPercent = 400

var (
	gcRelaxMu    sync.Mutex
	gcRelaxUsers int
	gcRelaxOld   int
)

// WithRelaxedGC runs a section with GC frequency lowered for allocation-heavy
// routing build phases. Nested and concurrent invocations share one relaxed
// section; the last release restores the previous GOGC and forces a GC so the
// temporary build garbage is reclaimed before returning to steady state.
func WithRelaxedGC() (restore func()) {
	gcRelaxMu.Lock()
	if gcRelaxUsers == 0 {
		gcRelaxOld = debug.SetGCPercent(heavyBuildGCPercent)
	}
	gcRelaxUsers++
	gcRelaxMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			gcRelaxMu.Lock()
			gcRelaxUsers--
			if gcRelaxUsers == 0 {
				old := gcRelaxOld
				debug.SetGCPercent(old)
				runtime.GC()
			}
			gcRelaxMu.Unlock()
		})
	}
}

type AliasOptimizer struct {
}

func (o *AliasOptimizer) Optimize(rules []*config_parser.RoutingRule) ([]*config_parser.RoutingRule, error) {
	for _, rule := range rules {
		for _, function := range rule.AndFunctions {
			switch function.Name {
			case "dport":
				function.Name = consts.Function_Port
			case "dip":
				function.Name = consts.Function_Ip
			}
			for _, param := range function.Params {
				if function.Name == consts.Function_Domain {
					// Rewrite to authoritative key name.
					switch param.Key {
					case "", "domain":
						param.Key = string(consts.RoutingDomainKey_Suffix)
					case "contains":
						param.Key = string(consts.RoutingDomainKey_Keyword)
					default:
					}
				}
			}
		}
	}
	return rules, nil
}

type MergeAndSortRulesOptimizer struct {
}

func (o *MergeAndSortRulesOptimizer) Optimize(rules []*config_parser.RoutingRule) ([]*config_parser.RoutingRule, error) {
	if len(rules) == 0 {
		return rules, nil
	}
	// Sort AndFunctions by FunctionName.
	for _, rule := range rules {
		sort.SliceStable(rule.AndFunctions, func(i, j int) bool {
			return rule.AndFunctions[i].Name < rule.AndFunctions[j].Name
		})
	}
	// Merge singleton rules with the same outbound.
	// NOTE: Only positive (non-inverted) functions can be safely merged.
	// For inverted rules, De Morgan's law breaks the equivalence:
	//   !f(a)->X OR !f(b)->X  !=  !f(a,b)->X
	// because sequential rule matching is OR while params within one
	// function are OR'd first and then inverted as a whole.
	var newRules []*config_parser.RoutingRule
	mergingRule := rules[0]
	for i := 1; i < len(rules); i++ {
		if len(mergingRule.AndFunctions) == 1 &&
			len(rules[i].AndFunctions) == 1 &&
			!mergingRule.AndFunctions[0].Not &&
			!rules[i].AndFunctions[0].Not &&
			mergingRule.AndFunctions[0].Name == rules[i].AndFunctions[0].Name &&
			rules[i].Outbound.MarshalString(true, false, true) == mergingRule.Outbound.MarshalString(true, false, true) {
			mergingRule.AndFunctions[0].Params = append(mergingRule.AndFunctions[0].Params, rules[i].AndFunctions[0].Params...)
		} else {
			newRules = append(newRules, mergingRule)
			mergingRule = rules[i]
		}
	}
	newRules = append(newRules, mergingRule)
	// Sort ParamList.
	for i := range newRules {
		for _, function := range newRules[i].AndFunctions {
			if function.Name == consts.Function_Ip || function.Name == consts.Function_SourceIp {
				// Sort by IPv4, IPv6, vals.
				sort.SliceStable(function.Params, func(i, j int) bool {
					vi, vj := 4, 4
					if strings.Contains(function.Params[i].Val, ":") {
						vi = 6
					}
					if strings.Contains(function.Params[j].Val, ":") {
						vj = 6
					}
					if vi == vj {
						return function.Params[i].Val < function.Params[j].Val
					}
					return vi < vj
				})
			} else {
				// Sort by keys, vals.
				sort.SliceStable(function.Params, func(i, j int) bool {
					if function.Params[i].Key == function.Params[j].Key {
						return function.Params[i].Val < function.Params[j].Val
					}
					return function.Params[i].Key < function.Params[j].Key
				})
			}
		}
	}
	return newRules, nil
}

type DeduplicateParamsOptimizer struct {
}

func deduplicateParams(list []*config_parser.Param) []*config_parser.Param {
	res := make([]*config_parser.Param, 0, len(list))
	m := make(map[string]struct{})
	for _, v := range list {
		if _, ok := m[v.String(true, false)]; ok {
			continue
		}
		m[v.String(true, false)] = struct{}{}
		res = append(res, v)
	}
	return res
}

func (o *DeduplicateParamsOptimizer) Optimize(rules []*config_parser.RoutingRule) ([]*config_parser.RoutingRule, error) {
	for _, rule := range rules {
		for _, f := range rule.AndFunctions {
			f.Params = deduplicateParams(f.Params)
		}
	}
	return rules, nil
}

type DatReaderOptimizer struct {
	LocationFinder *assets.LocationFinder
	Logger         *logrus.Logger
	mu             sync.Mutex
	// Cached slices are shared read-only across cache hits: callers receive
	// the exact same backing array and must not append to it, reorder it, or
	// mutate Param fields. Optimize only reads cached slices while building a
	// freshly allocated merged Params slice for each rule, so downstream
	// optimizers (MergeAndSort/Deduplicate) never touch this backing array.
	geoSiteCache map[string][]*config_parser.Param
	geoIpCache   map[string][]*config_parser.Param
}

// sharedParams returns the canonical read-only slice stored in the geo
// caches. When s carries spare capacity it is compacted once, so an
// accidental future append onto a cache-hit slice cannot overwrite entries
// shared with the cache. In the common case (cap == len) it returns s with
// no allocation.
func sharedParams(s []*config_parser.Param) []*config_parser.Param {
	if len(s) == 0 {
		return nil
	}
	if cap(s) == len(s) {
		return s
	}
	frozen := make([]*config_parser.Param, len(s))
	copy(frozen, s)
	return frozen
}

func (o *DatReaderOptimizer) initCacheLocked() {
	if o.geoSiteCache == nil {
		o.geoSiteCache = make(map[string][]*config_parser.Param)
	}
	if o.geoIpCache == nil {
		o.geoIpCache = make(map[string][]*config_parser.Param)
	}
}

func (o *DatReaderOptimizer) loadGeoSite(filename string, code string) (params []*config_parser.Param, err error) {
	if !strings.HasSuffix(filename, ".dat") {
		filename += ".dat"
	}

	cacheKey := strings.ToLower(filename + ":" + code)
	o.mu.Lock()
	o.initCacheLocked()
	if cached, ok := o.geoSiteCache[cacheKey]; ok {
		o.mu.Unlock()
		return cached, nil
	}
	o.mu.Unlock()

	filePath, err := o.LocationFinder.GetLocationAsset(o.Logger, filename)
	if err != nil {
		o.Logger.Debugf("Failed to read geosite \"%v:%v\": %v", filename, code, err)
		return nil, err
	}
	//o.Logger.Debugf("Read geosite \"%v:%v\" from %v", filename, code, filePath)
	code, attr, _ := strings.Cut(code, "@")
	// Direct wire-format decode: avoids building the protobuf object tree,
	// which was the dominant allocation source for large geosite files.
	domains, err := geodata.LoadGeoSiteLite(o.Logger, filePath, code, attr)
	if err != nil {
		return nil, err
	}
	// Back every expanded Param by one allocation instead of one per domain.
	objs := make([]config_parser.Param, len(domains))
	params = make([]*config_parser.Param, 0, len(domains))
	for i := range domains {
		key, ok := geoDomainRoutingKey(domains[i].Type)
		if !ok {
			continue
		}
		p := &objs[i]
		p.Key = key
		p.Val = domains[i].Value
		params = append(params, p)
	}

	// Share one read-only backing array between the cache and every hit.
	params = sharedParams(params)
	o.mu.Lock()
	o.initCacheLocked()
	o.geoSiteCache[cacheKey] = params
	o.mu.Unlock()

	return params, nil
}

// geoDomainRoutingKey maps a geosite Domain_Type to the corresponding routing
// domain key. Unknown types are dropped, matching the previous switch's
// default behavior.
func geoDomainRoutingKey(t geodata.Domain_Type) (string, bool) {
	switch t {
	case geodata.Domain_Full:
		return string(consts.RoutingDomainKey_Full), true
	case geodata.Domain_RootDomain:
		return string(consts.RoutingDomainKey_Suffix), true
	case geodata.Domain_Plain:
		return string(consts.RoutingDomainKey_Keyword), true
	case geodata.Domain_Regex:
		return string(consts.RoutingDomainKey_Regex), true
	default:
		return "", false
	}
}

func (o *DatReaderOptimizer) loadGeoIp(filename string, code string) (params []*config_parser.Param, err error) {
	if !strings.HasSuffix(filename, ".dat") {
		filename += ".dat"
	}

	cacheKey := strings.ToLower(filename + ":" + code)
	o.mu.Lock()
	o.initCacheLocked()
	if cached, ok := o.geoIpCache[cacheKey]; ok {
		o.mu.Unlock()
		return cached, nil
	}
	o.mu.Unlock()

	filePath, err := o.LocationFinder.GetLocationAsset(o.Logger, filename)
	if err != nil {
		o.Logger.Debugf("Failed to read geoip \"%v:%v\": %v", filename, code, err)
		return nil, err
	}
	//o.Logger.Debugf("Read geoip \"%v:%v\" from %v", filename, code, filePath)
	geoIp, err := geodata.UnmarshalGeoIp(o.Logger, filePath, code)
	if err != nil {
		return nil, err
	}
	if geoIp.InverseMatch {
		return nil, fmt.Errorf("not support inverse match yet")
	}
	for _, item := range geoIp.Cidr {
		ip, ok := netip.AddrFromSlice(item.Ip)
		if !ok {
			return nil, fmt.Errorf("bad geoip file: %v", filename)
		}
		params = append(params, &config_parser.Param{
			Key: "",
			Val: netip.PrefixFrom(ip, int(item.Prefix)).String(),
		})
	}

	// Share one read-only backing array between the cache and every hit.
	params = sharedParams(params)
	o.mu.Lock()
	o.initCacheLocked()
	o.geoIpCache[cacheKey] = params
	o.mu.Unlock()

	return params, nil
}

func (o *DatReaderOptimizer) Optimize(rules []*config_parser.RoutingRule) ([]*config_parser.RoutingRule, error) {
	// Process rules in parallel for better performance.
	// Limit concurrency to avoid overwhelming the system.
	type ruleResult struct {
		index int
		rule  *config_parser.RoutingRule
		err   error
	}

	numWorkers := min(len(rules), 4)

	sem := make(chan struct{}, numWorkers)
	results := make(chan ruleResult, len(rules))
	var wg sync.WaitGroup

	for i, rule := range rules {
		wg.Add(1)
		go func(idx int, r *config_parser.RoutingRule) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Process this rule's functions.
			for _, f := range r.AndFunctions {
				// Fast path: no geosite/geoip/ext expansion needed. Leave the
				// original Params slice untouched and avoid allocating.
				if !hasExpandableParam(f.Params) {
					continue
				}
				// Expand every param first so the merged slice can be allocated
				// once at its exact size. Appending hundreds of thousands of
				// expanded domains into a slice sized for the original param
				// count used to re-grow (and re-copy every pointer under write
				// barriers) ~log2(N) times.
				parts := make([][]*config_parser.Param, len(f.Params))
				total := 0
				for i, param := range f.Params {
					// Parse this param and replace it with more.
					var params []*config_parser.Param
					var loadErr error
					switch param.Key {
					case "geosite":
						params, loadErr = o.loadGeoSite("geosite", param.Val)
					case "geoip":
						params, loadErr = o.loadGeoIp("geoip", param.Val)
					case "ext":
						fields := strings.SplitN(param.Val, ":", 2)
						switch f.Name {
						case consts.Function_Domain, consts.Function_QName:
							params, loadErr = o.loadGeoSite(fields[0], fields[1])
						case consts.Function_Ip:
							params, loadErr = o.loadGeoIp(fields[0], fields[1])
						default:
							loadErr = fmt.Errorf("unsupported extension file extraction in function %v", f.Name)
						}
					default:
						// Keep this param.
						params = []*config_parser.Param{param}
					}
					if loadErr != nil {
						results <- ruleResult{idx, nil, loadErr}
						return
					}
					parts[i] = params
					total += len(params)
				}
				newParams := make([]*config_parser.Param, 0, total)
				for _, params := range parts {
					newParams = append(newParams, params...)
				}
				f.Params = newParams
			}
			results <- ruleResult{idx, r, nil}
		}(i, rule)
	}

	// Wait for all goroutines to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	newRules := make([]*config_parser.RoutingRule, len(rules))
	for result := range results {
		if result.err != nil {
			return nil, result.err
		}
		newRules[result.index] = result.rule
	}

	return newRules, nil
}

// hasExpandableParam reports whether any param requires DatReader expansion
// (geosite/geoip/ext).
func hasExpandableParam(params []*config_parser.Param) bool {
	for _, param := range params {
		switch param.Key {
		case "geosite", "geoip", "ext":
			return true
		}
	}
	return false
}
