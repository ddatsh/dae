/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"github.com/daeuniverse/dae/component/routing"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

// CompiledRequestRouting is shared by DNS consumers within one generation.
// Matcher and selector rules must not be modified after compilation. Connections,
// upstream initialization and callbacks belong to each consumer separately.
type CompiledRequestRouting struct {
	Matcher           *RequestMatcher
	HasDNSRules       bool
	SubscriptionRules []*config_parser.RoutingRule
	NodeRules         []*config_parser.RoutingRule
	SubNodeRules      []*config_parser.RoutingRule
}

func CompileRequestRouting(log *logrus.Logger, program *NormalizedRequestRoutingProgram, upstreamName2Id map[string]uint8) (*CompiledRequestRouting, error) {
	builder, err := NewRequestMatcherBuilderFromProgram(log, program, upstreamName2Id)
	if err != nil {
		return nil, err
	}
	matcher, err := builder.Build()
	if err != nil {
		return nil, err
	}
	// Do not retain the expanded DNS rules: their geosite parameter objects
	// are build-only data and can dwarf the compiled matcher in memory.
	return &CompiledRequestRouting{
		Matcher:           matcher,
		HasDNSRules:       len(program.Rules) != 0,
		SubscriptionRules: program.SubscriptionRules,
		NodeRules:         program.NodeRules,
		SubNodeRules:      program.SubNodeRules,
	}, nil
}

// NormalizedRequestRoutingProgram is the DNS request routing IR after
// optimizer application and internal-selector classification.
type NormalizedRequestRoutingProgram struct {
	routing.NormalizedProgram
	SubscriptionRules []*config_parser.RoutingRule
	NodeRules         []*config_parser.RoutingRule
	SubNodeRules      []*config_parser.RoutingRule
}

func NewNormalizedRequestRoutingProgram(
	rules []*config_parser.RoutingRule,
	fallback config.FunctionOrString,
	optimizers ...routing.RulesOptimizer,
) (*NormalizedRequestRoutingProgram, error) {
	var (
		normalizedRules []*config_parser.RoutingRule
		err             error
	)
	if len(optimizers) > 0 {
		normalizedRules, err = routing.ApplyRulesOptimizers(rules, optimizers...)
		if err != nil {
			return nil, err
		}
	} else {
		normalizedRules = routing.DeepCloneRules(rules)
	}
	dnsRules, subRules, nodeRules, subNodeRules, err := SplitRequestRules(normalizedRules)
	if err != nil {
		return nil, err
	}
	return &NormalizedRequestRoutingProgram{
		NormalizedProgram: routing.NormalizedProgram{
			Rules:    dnsRules,
			Fallback: fallback,
		},
		SubscriptionRules: subRules,
		NodeRules:         nodeRules,
		SubNodeRules:      subNodeRules,
	}, nil
}
