/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"fmt"
	"strconv"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/component/routing/domain_matcher"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

// UpstreamFilterMatcher re-routes or rejects requests AFTER the plain request
// routing has picked a target outbound. Inside a filter rule upstream(name)
// matches the outbound that the upstream-free request rules (and the request
// fallback) chose - the base decision. Filter rules keep their configured
// order and the first hit wins; when no filter rule hits, the base decision
// stands. This is what makes
//
//	qtype(aaaa, https) && upstream(remote) -> reject
//
// expressible directly in the request block: the request only needs to be
// destined to `remote`, no matter which qname rule or fallback sent it there.
type UpstreamFilterMatcher struct {
	domainMatcher routing.DomainMatcher // All domain matchSets use one DomainMatcher.

	matches []requestMatchSet
}

type UpstreamFilterMatcherBuilder struct {
	log                *logrus.Logger
	upstreamName2Id    map[string]uint8
	simulatedDomainSet []routing.DomainSet
	rules              []requestMatchSet
}

// NewUpstreamFilterMatcherFromRules builds the matcher from already-normalized
// filter rules (the rules SplitRequestRules classified as upstream-filter
// after optimizer application). There is no fallback of its own: a miss means
// "keep the base decision", which Match encodes by returning its base argument.
func NewUpstreamFilterMatcherFromRules(log *logrus.Logger, rules []*config_parser.RoutingRule, upstreamName2Id map[string]uint8) (b *UpstreamFilterMatcherBuilder, err error) {
	b = &UpstreamFilterMatcherBuilder{log: log, upstreamName2Id: upstreamName2Id}
	rulesBuilder := routing.NewRulesBuilder(log)
	b.registerRulesParsers(rulesBuilder)
	if err = rulesBuilder.Apply(rules); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *UpstreamFilterMatcherBuilder) registerRulesParsers(rulesBuilder *routing.RulesBuilder) {
	rulesBuilder.RegisterFunctionParser(consts.Function_QName, routing.PlainParserFactory(b.addQName))
	rulesBuilder.RegisterFunctionParser(consts.Function_QType, TypeParserFactory(b.addQType))
	rulesBuilder.RegisterFunctionParser(consts.Function_Upstream, routing.EmptyKeyPlainParserFactory(b.addUpstream))
}

func (b *UpstreamFilterMatcherBuilder) upstreamToId(upstream string) (upstreamId consts.DnsRequestOutboundIndex, err error) {
	switch upstream {
	case consts.DnsRequestOutboundIndex_Reject.String():
		upstreamId = consts.DnsRequestOutboundIndex_Reject
	case consts.DnsRequestOutboundIndex_AsIs.String():
		upstreamId = consts.DnsRequestOutboundIndex_AsIs
	case consts.DnsRequestOutboundIndex_LogicalAnd.String():
		upstreamId = consts.DnsRequestOutboundIndex_LogicalAnd
	case consts.DnsRequestOutboundIndex_LogicalOr.String():
		upstreamId = consts.DnsRequestOutboundIndex_LogicalOr
	default:
		_upstreamId, ok := b.upstreamName2Id[upstream]
		if !ok {
			return 0, fmt.Errorf("upstream %v not found; please define it in section \"dns.upstream\"", strconv.Quote(upstream))
		}
		upstreamId = consts.DnsRequestOutboundIndex(_upstreamId)
	}
	return upstreamId, nil
}

func (b *UpstreamFilterMatcherBuilder) addQName(f *config_parser.Function, key string, values []string, upstream *routing.Outbound) (err error) {
	switch consts.RoutingDomainKey(key) {
	case consts.RoutingDomainKey_Regex,
		consts.RoutingDomainKey_Full,
		consts.RoutingDomainKey_Keyword,
		consts.RoutingDomainKey_Suffix:
	default:
		return fmt.Errorf("addQName: unsupported key: %v", key)
	}
	b.simulatedDomainSet = append(b.simulatedDomainSet, routing.DomainSet{
		Key:       consts.RoutingDomainKey(key),
		RuleIndex: len(b.rules),
		Domains:   values,
	})
	upstreamId, err := b.upstreamToId(upstream.Name)
	if err != nil {
		return err
	}
	b.rules = append(b.rules, requestMatchSet{
		Type:     consts.MatchType_DomainSet,
		Not:      f.Not,
		Upstream: uint8(upstreamId),
	})
	return nil
}

func (b *UpstreamFilterMatcherBuilder) addQType(f *config_parser.Function, values []uint16, upstream *routing.Outbound) (err error) {
	for i, value := range values {
		upstreamName := consts.OutboundLogicalOr.String()
		if i == len(values)-1 {
			upstreamName = upstream.Name
		}
		upstreamId, err := b.upstreamToId(upstreamName)
		if err != nil {
			return err
		}
		b.rules = append(b.rules, requestMatchSet{
			Type:     consts.MatchType_QType,
			Value:    value,
			Not:      f.Not,
			Upstream: uint8(upstreamId),
		})
	}
	return nil
}

func (b *UpstreamFilterMatcherBuilder) addUpstream(f *config_parser.Function, values []string, upstream *routing.Outbound) (err error) {
	for i, value := range values {
		upstreamName := consts.OutboundLogicalOr.String()
		if i == len(values)-1 {
			upstreamName = upstream.Name
		}
		upstreamId, err := b.upstreamToId(upstreamName)
		if err != nil {
			return err
		}
		lastUpstreamId, err := b.upstreamToId(value)
		if err != nil {
			return err
		}
		b.rules = append(b.rules, requestMatchSet{
			Type:     consts.MatchType_Upstream,
			Value:    uint16(lastUpstreamId),
			Not:      f.Not,
			Upstream: uint8(upstreamId),
		})
	}
	return nil
}

func (b *UpstreamFilterMatcherBuilder) Build() (matcher *UpstreamFilterMatcher, err error) {
	var m UpstreamFilterMatcher
	// Build domainMatcher.
	m.domainMatcher = domain_matcher.NewAhocorasickSlimtrie(b.log, consts.MaxMatchSetLen)
	for _, domains := range b.simulatedDomainSet {
		m.domainMatcher.AddSet(domains.RuleIndex, domains.Domains, domains.Key)
	}
	if err = m.domainMatcher.Build(); err != nil {
		return nil, err
	}
	m.matches = b.rules
	return &m, nil
}

// Match evaluates the filter rules against qName/qType and the base decision.
// A returned error means the match sets are malformed, which Build already
// prevents; a miss is not an error and yields base unchanged.
func (m *UpstreamFilterMatcher) Match(
	qName string,
	qType uint16,
	base consts.DnsRequestOutboundIndex,
) (upstreamIndex consts.DnsRequestOutboundIndex, err error) {
	var domainMatchBitmap []uint32
	if qName != "" {
		domainMatchBitmap = m.domainMatcher.MatchDomainBitmap(qName)
	}

	goodSubrule := false
	badRule := false
	for i, match := range m.matches {
		if badRule || goodSubrule {
			goto beforeNextLoop
		}
		switch match.Type {
		case consts.MatchType_DomainSet:
			if domainMatchBitmap != nil && (domainMatchBitmap[i/32]>>(i%32))&1 > 0 {
				goodSubrule = true
			}
		case consts.MatchType_QType:
			if qType == match.Value {
				goodSubrule = true
			}
		case consts.MatchType_Upstream:
			if base == consts.DnsRequestOutboundIndex(match.Value) {
				goodSubrule = true
			}
		default:
			return 0, fmt.Errorf("unknown match type: %v", match.Type)
		}
	beforeNextLoop:
		upstream := consts.DnsRequestOutboundIndex(match.Upstream)
		if upstream != consts.DnsRequestOutboundIndex_LogicalOr {
			// This match_set reaches the end of subrule.
			// We are now at end of rule, or next match_set belongs to another
			// subrule.

			if goodSubrule == match.Not {
				// This subrule does not hit.
				badRule = true
			}

			// Reset goodSubrule.
			goodSubrule = false
		}

		if upstream&consts.DnsRequestOutboundIndex_LogicalMask !=
			consts.DnsRequestOutboundIndex_LogicalMask {
			// Tail of a rule (line).
			// Decide whether to hit.
			if !badRule {
				return upstream, nil
			}
			badRule = false
		}
	}
	// No filter rule hit: keep the base decision.
	return base, nil
}
