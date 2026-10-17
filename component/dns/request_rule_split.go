/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"fmt"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type RequestRuleCategory int

const (
	RequestRuleCategoryDNS RequestRuleCategory = iota
	RequestRuleCategorySub
	RequestRuleCategoryNode
	RequestRuleCategorySubNode
	// RequestRuleCategoryUpstreamFilter holds rules that reference
	// upstream(name). Such a rule is not a plain routing rule: upstream(name)
	// matches the outbound that the upstream-free request rules (and the
	// fallback) would choose, so these rules are evaluated after the base
	// decision is known and can re-route or reject requests destined to a
	// specific upstream.
	RequestRuleCategoryUpstreamFilter
)

func SplitRequestRules(
	rules []*config_parser.RoutingRule,
) (
	dnsRules []*config_parser.RoutingRule,
	subRules []*config_parser.RoutingRule,
	nodeRules []*config_parser.RoutingRule,
	subNodeRules []*config_parser.RoutingRule,
	upstreamFilterRules []*config_parser.RoutingRule,
	err error,
) {
	for _, rule := range rules {
		category, classifyErr := classifyRequestRule(rule)
		if classifyErr != nil {
			return nil, nil, nil, nil, nil, classifyErr
		}
		switch category {
		case RequestRuleCategoryDNS:
			dnsRules = append(dnsRules, rule)
		case RequestRuleCategorySub:
			subRules = append(subRules, rule)
		case RequestRuleCategoryNode:
			nodeRules = append(nodeRules, rule)
		case RequestRuleCategorySubNode:
			subNodeRules = append(subNodeRules, rule)
		case RequestRuleCategoryUpstreamFilter:
			upstreamFilterRules = append(upstreamFilterRules, rule)
		default:
			return nil, nil, nil, nil, nil, fmt.Errorf("unknown request rule category: %v", category)
		}
	}
	return dnsRules, subRules, nodeRules, subNodeRules, upstreamFilterRules, nil
}

func classifyRequestRule(rule *config_parser.RoutingRule) (RequestRuleCategory, error) {
	if len(rule.AndFunctions) == 0 {
		return RequestRuleCategoryDNS, nil
	}

	var (
		internalCategory RequestRuleCategory
		hasInternal      bool
		hasDNS           bool
		hasUpstream      bool
	)
	for _, f := range rule.AndFunctions {
		switch f.Name {
		case consts.Function_QName, consts.Function_QType:
			if hasInternal {
				return 0, fmt.Errorf("cannot mix %q/%q with internal dae DNS selectors in one rule: %v",
					consts.Function_QName, consts.Function_QType, rule.String(false, false, false))
			}
			hasDNS = true
		case consts.Function_Upstream:
			if hasInternal {
				return 0, fmt.Errorf("cannot mix %q with internal dae DNS selectors in one rule: %v",
					consts.Function_Upstream, rule.String(false, false, false))
			}
			hasUpstream = true
		case "sub":
			if hasDNS {
				return 0, fmt.Errorf("cannot mix %q/%q with internal dae DNS selectors in one rule: %v",
					consts.Function_QName, consts.Function_QType, rule.String(false, false, false))
			}
			if hasUpstream {
				return 0, fmt.Errorf("cannot mix %q with internal dae DNS selectors in one rule: %v",
					consts.Function_Upstream, rule.String(false, false, false))
			}
			if !hasInternal {
				internalCategory = RequestRuleCategorySub
				hasInternal = true
			} else if internalCategory != RequestRuleCategorySub {
				return 0, fmt.Errorf("cannot mix internal dae DNS selectors in one rule: %v", rule.String(false, false, false))
			}
		case "node":
			if hasDNS {
				return 0, fmt.Errorf("cannot mix %q/%q with internal dae DNS selectors in one rule: %v",
					consts.Function_QName, consts.Function_QType, rule.String(false, false, false))
			}
			if hasUpstream {
				return 0, fmt.Errorf("cannot mix %q with internal dae DNS selectors in one rule: %v",
					consts.Function_Upstream, rule.String(false, false, false))
			}
			if !hasInternal {
				internalCategory = RequestRuleCategoryNode
				hasInternal = true
			} else if internalCategory != RequestRuleCategoryNode {
				return 0, fmt.Errorf("cannot mix internal dae DNS selectors in one rule: %v", rule.String(false, false, false))
			}
		case "subnode":
			if hasDNS {
				return 0, fmt.Errorf("cannot mix %q/%q with internal dae DNS selectors in one rule: %v",
					consts.Function_QName, consts.Function_QType, rule.String(false, false, false))
			}
			if hasUpstream {
				return 0, fmt.Errorf("cannot mix %q with internal dae DNS selectors in one rule: %v",
					consts.Function_Upstream, rule.String(false, false, false))
			}
			if !hasInternal {
				internalCategory = RequestRuleCategorySubNode
				hasInternal = true
			} else if internalCategory != RequestRuleCategorySubNode {
				return 0, fmt.Errorf("cannot mix internal dae DNS selectors in one rule: %v", rule.String(false, false, false))
			}
		default:
			if hasInternal {
				return 0, fmt.Errorf("cannot mix internal dae DNS selectors with %q in one rule: %v", f.Name, rule.String(false, false, false))
			}
			if hasUpstream {
				return 0, fmt.Errorf("cannot mix %q with %q in one rule: %v",
					consts.Function_Upstream, f.Name, rule.String(false, false, false))
			}
		}
	}

	if hasInternal {
		return internalCategory, nil
	}
	if hasUpstream {
		return RequestRuleCategoryUpstreamFilter, nil
	}
	return RequestRuleCategoryDNS, nil
}
