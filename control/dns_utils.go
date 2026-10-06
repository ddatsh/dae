/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"fmt"
	"strconv"
	"strings"

	dnsmessage "github.com/miekg/dns"
)

type RscWrapper struct {
	Rsc dnsmessage.RR
}

func (w RscWrapper) String() string {
	var strBody string
	switch body := w.Rsc.(type) {
	case *dnsmessage.A:
		strBody = body.A.String()
	case *dnsmessage.AAAA:
		strBody = body.AAAA.String()
	case *dnsmessage.CNAME:
		strBody = body.Target
	default:
		strBody = body.String()
	}
	return fmt.Sprintf("%v(%v): %v", strings.TrimSuffix(w.Rsc.Header().Name, "."), QtypeToString(w.Rsc.Header().Rrtype), strBody)
}

// FormatDnsRsc formats the answer section as a name-resolution chain. The
// first record of a chain is rendered as name(type), and every CNAME target
// continuing it is appended after " > "; the terminal A/AAAA addresses that
// end the chain follow the last name after ": " (e.g.
// "a.example(CNAME) > b.example: 1.2.3.4"). A record that does not continue
// the current chain starts a new group separated by "; ".
func FormatDnsRsc(ans []dnsmessage.RR) string {
	var groups []string
	var chain []string
	var addrs []string
	lastTarget := ""

	flushAddrs := func() {
		if len(addrs) > 0 {
			chain = append(chain, strings.Join(addrs, ", "))
			addrs = nil
		}
	}
	flushChain := func() {
		if len(chain) > 0 {
			s := strings.Join(chain, " > ")
			if len(addrs) > 0 {
				// Addresses terminate the chain: they follow the last name
				// after ": " instead of another " > " hop.
				s += ": " + strings.Join(addrs, ", ")
				addrs = nil
			}
			groups = append(groups, s)
			chain = nil
		} else if len(addrs) > 0 {
			groups = append(groups, strings.Join(addrs, ", "))
			addrs = nil
		}
		lastTarget = ""
	}

	for _, a := range ans {
		hdr := a.Header()
		name := strings.TrimSuffix(hdr.Name, ".")
		continues := len(chain) > 0 && strings.EqualFold(name, lastTarget)

		switch rr := a.(type) {
		case *dnsmessage.CNAME:
			if !continues {
				flushChain()
				chain = append(chain, name+"("+QtypeToString(hdr.Rrtype)+")")
			} else {
				flushAddrs()
			}
			lastTarget = strings.TrimSuffix(rr.Target, ".")
			chain = append(chain, lastTarget)
		case *dnsmessage.A:
			if !continues {
				flushChain()
				chain = append(chain, name+"("+QtypeToString(hdr.Rrtype)+")")
				lastTarget = name
			}
			addrs = append(addrs, rr.A.String())
		case *dnsmessage.AAAA:
			if !continues {
				flushChain()
				chain = append(chain, name+"("+QtypeToString(hdr.Rrtype)+")")
				lastTarget = name
			}
			addrs = append(addrs, rr.AAAA.String())
		default:
			if !continues {
				flushChain()
			} else {
				flushAddrs()
			}
			chain = append(chain, RscWrapper{Rsc: a}.String())
			lastTarget = ""
		}
	}
	flushChain()

	return strings.Join(groups, "; ")
}

func QtypeToString(qtype uint16) string {
	str, ok := dnsmessage.TypeToString[qtype]
	if !ok {
		str = strconv.Itoa(int(qtype))
	}
	return str
}
