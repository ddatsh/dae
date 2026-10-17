/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@daeuniverse.org>
 */

package dns

import (
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

func TestSplitRequestRulesSeparatesDNSAndInternalSelectors(t *testing.T) {
	dnsRule := testRequestRule(
		"alidns",
		testFunction("qname", testParam("suffix", "example.com")),
	)
	subRule := testRequestRule(
		"subdns",
		testFunction("sub", testParam("", "my_sub")),
	)
	nodeRule := testRequestRule(
		"nodedns",
		testFunction("node", testParam("", "hk-01")),
	)
	subNodeRule := testRequestRule(
		"subnodedns",
		testFunction("subnode", testParam("subtag", "my_sub")),
	)

	dnsRules, subRules, nodeRules, subNodeRules, upstreamFilterRules, err := SplitRequestRules([]*config_parser.RoutingRule{
		dnsRule,
		subRule,
		nodeRule,
		subNodeRule,
	})
	if err != nil {
		t.Fatalf("SplitRequestRules() error = %v", err)
	}

	if len(dnsRules) != 1 || dnsRules[0] != dnsRule {
		t.Fatalf("unexpected dns rules: %#v", dnsRules)
	}
	if len(subRules) != 1 || subRules[0] != subRule {
		t.Fatalf("unexpected sub rules: %#v", subRules)
	}
	if len(nodeRules) != 1 || nodeRules[0] != nodeRule {
		t.Fatalf("unexpected node rules: %#v", nodeRules)
	}
	if len(subNodeRules) != 1 || subNodeRules[0] != subNodeRule {
		t.Fatalf("unexpected subnode rules: %#v", subNodeRules)
	}
	if len(upstreamFilterRules) != 0 {
		t.Fatalf("unexpected upstream filter rules: %#v", upstreamFilterRules)
	}
}

func TestSplitRequestRulesSeparatesUpstreamFilterRules(t *testing.T) {
	filterRule := testRequestRule(
		"reject",
		testFunction("qtype", testParam("", "aaaa"), testParam("", "https")),
		testFunction("upstream", testParam("", "remote")),
	)

	dnsRules, _, _, _, upstreamFilterRules, err := SplitRequestRules([]*config_parser.RoutingRule{
		filterRule,
	})
	if err != nil {
		t.Fatalf("SplitRequestRules() error = %v", err)
	}
	if len(dnsRules) != 0 {
		t.Fatalf("upstream filter rule must not land in the base dns rules: %#v", dnsRules)
	}
	if len(upstreamFilterRules) != 1 || upstreamFilterRules[0] != filterRule {
		t.Fatalf("unexpected upstream filter rules: %#v", upstreamFilterRules)
	}
}

func TestSplitRequestRulesRejectsUpstreamWithInternalSelectors(t *testing.T) {
	_, _, _, _, _, err := SplitRequestRules([]*config_parser.RoutingRule{
		testRequestRule(
			"alidns",
			testFunction("upstream", testParam("", "remote")),
			testFunction("sub", testParam("", "my_sub")),
		),
	})
	if err == nil {
		t.Fatal("expected mixed upstream/sub rule to fail")
	}
	if !strings.Contains(err.Error(), "cannot mix") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSplitRequestRulesRejectsMixedDNSAndInternalSelectors(t *testing.T) {
	_, _, _, _, _, err := SplitRequestRules([]*config_parser.RoutingRule{
		testRequestRule(
			"alidns",
			testFunction("qname", testParam("suffix", "example.com")),
			testFunction("sub", testParam("", "my_sub")),
		),
	})
	if err == nil {
		t.Fatal("expected mixed qname/sub rule to fail")
	}
	if !strings.Contains(err.Error(), "cannot mix") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSplitRequestRulesRejectsMixedInternalSelectors(t *testing.T) {
	_, _, _, _, _, err := SplitRequestRules([]*config_parser.RoutingRule{
		testRequestRule(
			"alidns",
			testFunction("node", testParam("", "hk-01")),
			testFunction("subnode", testParam("subtag", "my_sub")),
		),
	})
	if err == nil {
		t.Fatal("expected mixed node/subnode rule to fail")
	}
	if !strings.Contains(err.Error(), "cannot mix internal dae DNS selectors") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func testRequestRule(outbound string, andFunctions ...*config_parser.Function) *config_parser.RoutingRule {
	return &config_parser.RoutingRule{
		AndFunctions: andFunctions,
		Outbound:     config_parser.Function{Name: outbound},
	}
}

func testFunction(name string, params ...*config_parser.Param) *config_parser.Function {
	return &config_parser.Function{
		Name:   name,
		Params: params,
	}
}

func testParam(key, value string) *config_parser.Param {
	return &config_parser.Param{
		Key: key,
		Val: value,
	}
}
