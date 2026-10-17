/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package dns

import (
	"context"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/config"
	config_parser "github.com/daeuniverse/dae/pkg/config_parser"
	dnsmessage "github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// parseDnsForFilterTest parses a full config and returns just the dns section,
// the same way the run path consumes it.
func parseDnsForFilterTest(t *testing.T, dnsBlock string) *config.Dns {
	t.Helper()
	sections, err := config_parser.Parse("global {}\ndns {\n" + dnsBlock + "\n}\nrouting {\n fallback: direct\n}\n")
	require.NoError(t, err)
	conf, err := config.New(sections)
	require.NoError(t, err)
	return &conf.Dns
}

const upstreamFilterTestBlock = ` upstream {
  remote: 'udp://192.0.2.53:53'
  local: 'udp://192.0.2.54:53'
 }
`

func newDnsForFilterTest(t *testing.T, dnsCfg *config.Dns) *Dns {
	t.Helper()
	s, err := New(dnsCfg, &NewOption{
		Logger:                logrus.New(),
		UpstreamReadyCallback: func(*Upstream) error { return nil },
	})
	require.NoError(t, err)
	return s
}

// TestRequestUpstreamFilterRejectsDestinedQueries covers the canonical
// configuration:
//
//	qtype(aaaa, https) && upstream(remote) -> reject
//	qname(suffix: example.com) -> remote
//	fallback: local
//
// The filter must intercept exactly the requests whose base decision is the
// named upstream, no matter which base rule (qname here, or the fallback)
// produced it.
func TestRequestUpstreamFilterRejectsDestinedQueries(t *testing.T) {
	dnsCfg := parseDnsForFilterTest(t, upstreamFilterTestBlock+` routing {
  request {
   qtype(aaaa, https) && upstream(remote) -> reject
   qname(suffix: example.com) -> remote
   fallback: local
  }
 }`)
	s := newDnsForFilterTest(t, dnsCfg)

	ctx := context.Background()
	remoteIdx := consts.DnsRequestOutboundIndex(0)
	localIdx := consts.DnsRequestOutboundIndex(1)

	// AAAA for example.com: base routes to remote via qname -> reject.
	index, upstream, err := s.RequestSelect(ctx, dnsmessage.CanonicalName("a.example.com"), dnsmessage.TypeAAAA)
	require.NoError(t, err)
	require.Equal(t, consts.DnsRequestOutboundIndex_Reject, index)
	require.Nil(t, upstream)

	// HTTPS (65) for example.com: same.
	index, upstream, err = s.RequestSelect(ctx, dnsmessage.CanonicalName("a.example.com"), 65)
	require.NoError(t, err)
	require.Equal(t, consts.DnsRequestOutboundIndex_Reject, index)
	require.Nil(t, upstream)

	// A for example.com: base routes to remote, qtype misses -> remote.
	index, upstream, err = s.RequestSelect(ctx, dnsmessage.CanonicalName("a.example.com"), dnsmessage.TypeA)
	require.NoError(t, err)
	require.Equal(t, remoteIdx, index)
	require.NotNil(t, upstream)

	// AAAA for another domain: base falls back to local, upstream misses -> local.
	index, upstream, err = s.RequestSelect(ctx, dnsmessage.CanonicalName("other.test."), dnsmessage.TypeAAAA)
	require.NoError(t, err)
	require.Equal(t, localIdx, index)
	require.NotNil(t, upstream)
}

// TestRequestUpstreamFilterViaFallbackOnly verifies the filter also intercepts
// when the base decision comes from the fallback alone.
func TestRequestUpstreamFilterViaFallbackOnly(t *testing.T) {
	dnsCfg := parseDnsForFilterTest(t, upstreamFilterTestBlock+` routing {
  request {
   qtype(aaaa, https) && upstream(remote) -> reject
   fallback: remote
  }
 }`)
	s := newDnsForFilterTest(t, dnsCfg)

	ctx := context.Background()
	index, upstream, err := s.RequestSelect(ctx, dnsmessage.CanonicalName("anything.test."), dnsmessage.TypeAAAA)
	require.NoError(t, err)
	require.Equal(t, consts.DnsRequestOutboundIndex_Reject, index)
	require.Nil(t, upstream)

	index, upstream, err = s.RequestSelect(ctx, dnsmessage.CanonicalName("anything.test."), dnsmessage.TypeA)
	require.NoError(t, err)
	require.Equal(t, consts.DnsRequestOutboundIndex(0), index)
	require.NotNil(t, upstream)
}

// TestRequestUpstreamFilterReroutes verifies a filter rule may also send the
// request to a different upstream instead of rejecting it.
func TestRequestUpstreamFilterReroutes(t *testing.T) {
	dnsCfg := parseDnsForFilterTest(t, upstreamFilterTestBlock+` routing {
  request {
   qtype(aaaa) && upstream(remote) -> local
   fallback: remote
  }
 }`)
	s := newDnsForFilterTest(t, dnsCfg)

	index, upstream, err := s.RequestSelect(context.Background(), dnsmessage.CanonicalName("anything.test."), dnsmessage.TypeAAAA)
	require.NoError(t, err)
	require.Equal(t, consts.DnsRequestOutboundIndex(1), index)
	require.NotNil(t, upstream)
}

// TestRequestUpstreamFilterUnknownUpstreamName makes sure an undefined
// upstream name fails at build time, the same verdict validate reports.
func TestRequestUpstreamFilterUnknownUpstreamName(t *testing.T) {
	dnsCfg := parseDnsForFilterTest(t, upstreamFilterTestBlock+` routing {
  request {
   qtype(aaaa) && upstream(nosuchupstream) -> reject
   fallback: remote
  }
 }`)
	_, err := New(dnsCfg, &NewOption{
		Logger:                logrus.New(),
		UpstreamReadyCallback: func(*Upstream) error { return nil },
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "nosuchupstream")
}
