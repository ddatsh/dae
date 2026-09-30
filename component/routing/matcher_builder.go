/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package routing

import (
	"fmt"
	"strconv"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/sirupsen/logrus"
)

type DomainSet struct {
	Key       consts.RoutingDomainKey
	RuleIndex int
	Domains   []string
}

type Outbound struct {
	Name string
	Mark uint32
	Must bool
}

type RulesBuilder struct {
	log     *logrus.Logger
	parsers map[string]FunctionParser
}

func NewRulesBuilder(log *logrus.Logger) *RulesBuilder {
	return &RulesBuilder{
		log:     log,
		parsers: make(map[string]FunctionParser),
	}
}

func (b *RulesBuilder) RegisterFunctionParser(funcName string, parser FunctionParser) {
	b.parsers[funcName] = parser
}

func (b *RulesBuilder) Apply(rules []*config_parser.RoutingRule) (err error) {
	for _, rule := range rules {
		/*
			if b.log.IsLevelEnabled(logrus.DebugLevel) {
				b.log.Debugln("[rule]", rule.String(true, false, false))
			}
		*/
		outbound, err := ParseOutbound(&rule.Outbound)
		if err != nil {
			return err
		}

		// rule is like: domain(domain:baidu.com) && port(443) -> proxy
		for iFunc, f := range rule.AndFunctions {
			// f is like: domain(domain:baidu.com)
			functionParser, ok := b.parsers[f.Name]
			if !ok {
				return fmt.Errorf("unknown function: %v", f.Name)
			}
			paramValueGroups, keyOrder := groupParamValuesByKey(f.Params)
			for jMatchSet, key := range keyOrder {
				paramValueGroup := paramValueGroups[key]
				// Preprocess the outbound.
				overrideOutbound := &Outbound{
					Name: consts.OutboundLogicalOr.String(),
					Mark: outbound.Mark,
					Must: outbound.Must,
				}
				if jMatchSet == len(keyOrder)-1 {
					overrideOutbound.Name = consts.OutboundLogicalAnd.String()
					if iFunc == len(rule.AndFunctions)-1 {
						overrideOutbound.Name = outbound.Name
					}
				}

				{
					// Debug
					/*
						symNot := ""
						if f.Not {
							symNot = "!"
						}
						b.log.Debugf("\t%v%v(%v) -> %v", symNot, f.Name, key, overrideOutbound.Name)
					*/
				}

				if err = functionParser(b.log, f, key, paramValueGroup, overrideOutbound); err != nil {
					return fmt.Errorf("failed to parse '%v': %w", f.String(false, false, false), err)
				}
			}
		}
	}
	return nil
}

func groupParamValuesByKey(params []*config_parser.Param) (keyToValues map[string][]string, keyOrder []string) {
	groups := make(map[string][]string)

	if len(params) == 0 {
		return groups, nil
	}

	// Most expanded domain rules have only one key. Avoid map lookups per
	// value in that case, while retaining first-seen order for mixed rules.
	key := params[0].Key
	singleKey := true
	for _, param := range params[1:] {
		if param.Key != key {
			singleKey = false
			break
		}
	}
	if singleKey {
		values := make([]string, len(params))
		for i, param := range params {
			values[i] = param.Val
		}
		groups[key] = values
		return groups, []string{key}
	}

	// Expanded geosite rules can contain hundreds of thousands of values.
	// Count first to avoid copying pointer-bearing strings during slice growth.
	counts := make(map[string]int)
	for _, param := range params {
		if _, ok := counts[param.Key]; !ok {
			keyOrder = append(keyOrder, param.Key)
		}
		counts[param.Key]++
	}
	for _, k := range keyOrder {
		groups[k] = make([]string, 0, counts[k])
	}
	for _, param := range params {
		groups[param.Key] = append(groups[param.Key], param.Val)
	}

	return groups, keyOrder
}

func ParseOutbound(rawOutbound *config_parser.Function) (outbound *Outbound, err error) {
	outbound = &Outbound{
		Name: rawOutbound.Name,
		Mark: 0,
		Must: false,
	}
	for _, p := range rawOutbound.Params {
		switch p.Key {
		case consts.OutboundParam_Mark:
			var _mark uint64
			_mark, err = strconv.ParseUint(p.Val, 0, 32)
			if err != nil {
				return nil, fmt.Errorf("failed to parse mark: %w", err)
			}
			outbound.Mark = uint32(_mark)
		case "":
			if p.Val == "must" {
				outbound.Must = true
			} else {
				return nil, fmt.Errorf("unknown outbound param: %v", p.Val)
			}
		default:
			return nil, fmt.Errorf("unknown outbound param key: %v", p.Key)
		}
	}
	return outbound, nil
}
