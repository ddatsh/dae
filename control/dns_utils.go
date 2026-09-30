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

func FormatDnsRsc(ans []dnsmessage.RR) string {
	grouped := make(map[string][]string)
	var order []string

	for _, a := range ans {
		s := RscWrapper{Rsc: a}.String()
		parts := strings.SplitN(s, ": ", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := parts[0], parts[1]
		if _, ok := grouped[key]; !ok {
			order = append(order, key)
		}
		grouped[key] = append(grouped[key], strings.TrimSuffix(val, "."))
	}

	var w []string
	for _, key := range order {
		w = append(w, key+": "+strings.Join(grouped[key], ", "))
	}
	return strings.Join(w, "; ")
}

func QtypeToString(qtype uint16) string {
	str, ok := dnsmessage.TypeToString[qtype]
	if !ok {
		str = strconv.Itoa(int(qtype))
	}
	return str
}
