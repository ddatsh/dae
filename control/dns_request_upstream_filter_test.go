/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"testing"

	componentdns "github.com/daeuniverse/dae/component/dns"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// TestPhase0DnsRequestUpstreamFilter rejects AAAA/HTTPS requests destined to a
// named upstream directly in the request block:
//
//	request {
//	  qtype(aaaa, https) && upstream(remote) -> reject
//	  fallback: remote
//	}
//
// The rejection must happen before any upstream traffic: the forwarder must
// not be called for AAAA/HTTPS, while A queries still reach the upstream.
func TestPhase0DnsRequestUpstreamFilter(t *testing.T) {
	cfg := &config.Dns{
		Upstream: []config.KeyableString{
			"remote:udp://192.0.2.53:53",
		},
		Routing: config.DnsRouting{
			Request: config.DnsRequestRouting{
				Rules: []*config_parser.RoutingRule{
					{
						AndFunctions: []*config_parser.Function{
							{
								Name: "qtype",
								Params: []*config_parser.Param{
									{Val: "aaaa"},
									{Val: "https"},
								},
							},
							{
								Name:   "upstream",
								Params: []*config_parser.Param{{Val: "remote"}},
							},
						},
						Outbound: config_parser.Function{Name: "reject"},
					},
				},
				Fallback: config.FunctionOrString("remote"),
			},
			Response: config.DnsResponseRouting{Fallback: config.FunctionOrString("accept")},
		},
	}
	ctrl := newCorpusControllerWithDefaultChooser(t, cfg)

	var forwards int
	installCorpusDnsForwarderFactory(t, func(*componentdns.Upstream, dialArgument, *logrus.Logger) (DnsForwarder, error) {
		return &stubDnsForwarder{forward: func(_ context.Context, raw []byte) (*dnsmessage.Msg, error) {
			forwards++
			q := new(dnsmessage.Msg)
			if err := q.Unpack(raw); err != nil {
				return nil, err
			}
			resp := new(dnsmessage.Msg)
			resp.SetReply(q)
			resp.Answer = []dnsmessage.RR{
				&dnsmessage.A{
					Hdr: dnsmessage.RR_Header{
						Name:   q.Question[0].Name,
						Rrtype: dnsmessage.TypeA,
						Class:  dnsmessage.ClassINET,
						Ttl:    60,
					},
					A: []byte{203, 0, 113, 77},
				},
			}
			return resp, nil
		}}, nil
	})

	// AAAA: rejected before dialing the upstream.
	resp := replayPhase0DnsRoutingQuery(t, ctrl, "example.test.", dnsmessage.TypeAAAA)
	if len(resp.Answer) != 0 {
		t.Fatalf("AAAA destined to remote: got %d answers, want 0 (rejected)", len(resp.Answer))
	}
	if forwards != 0 {
		t.Fatalf("AAAA destined to remote: forwarder called %d times, want 0", forwards)
	}

	// HTTPS (65): rejected before dialing the upstream.
	resp = replayPhase0DnsRoutingQuery(t, ctrl, "example.test.", 65)
	if len(resp.Answer) != 0 {
		t.Fatalf("HTTPS destined to remote: got %d answers, want 0 (rejected)", len(resp.Answer))
	}
	if forwards != 0 {
		t.Fatalf("HTTPS destined to remote: forwarder called %d times, want 0", forwards)
	}

	// A: passes through to remote.
	resp = replayPhase0DnsRoutingQuery(t, ctrl, "example.test.", dnsmessage.TypeA)
	if forwards != 1 {
		t.Fatalf("A destined to remote: forwarder called %d times, want 1", forwards)
	}
	if got := dnsAnswerIPv4(t, resp); got != "203.0.113.77" {
		t.Fatalf("A destined to remote: answer = %s, want 203.0.113.77", got)
	}
}
