/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package geodata

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func TestEmitBytesRejectsOversizedEntry(t *testing.T) {
	path := t.TempDir() + "/oversized.dat"
	data := append([]byte{0x0a}, protowire.AppendVarint(nil, maxGeoEntryLength+1)...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = file.Close() }()

	_, err = emitBytes(file, "CN")
	if !errors.Is(err, errInvalidGeodataVarintLength) {
		t.Fatalf("expected oversized-entry error, got %v", err)
	}
}

func TestEmitBytesRejectsUnterminatedVarint(t *testing.T) {
	path := t.TempDir() + "/unterminated.dat"
	data := make([]byte, binary.MaxVarintLen64+2)
	data[0] = 0x0a
	for i := 1; i < len(data); i++ {
		data[i] = 0x80
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer func() { _ = file.Close() }()

	_, err = emitBytes(file, "CN")
	if !errors.Is(err, errInvalidGeodataVarintLength) {
		t.Fatalf("expected unterminated-varint error, got %v", err)
	}
}

func writeGeoSiteList(t *testing.T, list *GeoSiteList) string {
	t.Helper()
	raw, err := proto.Marshal(list)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	path := t.TempDir() + "/geosite.dat"
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestLoadGeoSiteLite(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	list := &GeoSiteList{Entry: []*GeoSite{
		{CountryCode: "cn", Domain: []*Domain{
			{Type: Domain_Plain, Value: "plain.test"},
			{Type: Domain_Regex, Value: "regex.test"},
			{Type: Domain_RootDomain, Value: "suffix.test"},
			{Type: Domain_Full, Value: "full.test"},
			{Type: Domain_Full, Value: "ads.test", Attribute: []*Domain_Attribute{{Key: "ads"}}},
			{Type: Domain_Plain, Value: "news.test", Attribute: []*Domain_Attribute{{Key: "news"}}},
		}},
		{CountryCode: "us", Domain: []*Domain{
			{Type: Domain_Full, Value: "us.test"},
		}},
	}}
	path := writeGeoSiteList(t, list)

	got, err := LoadGeoSiteLite(log, path, "CN", "")
	if err != nil {
		t.Fatalf("LoadGeoSiteLite: %v", err)
	}
	want := list.Entry[0].Domain
	if len(got) != len(want) {
		t.Fatalf("got %d domains, want %d", len(got), len(want))
	}
	for i, d := range want {
		if got[i].Type != d.Type || got[i].Value != d.Value {
			t.Fatalf("domain %d = (%v, %q), want (%v, %q)", i, got[i].Type, got[i].Value, d.Type, d.Value)
		}
	}

	// Attribute filter is case-insensitive on both code and key.
	ads, err := LoadGeoSiteLite(log, path, "cn", "ADS")
	if err != nil {
		t.Fatalf("attr filter: %v", err)
	}
	if len(ads) != 1 || ads[0].Value != "ads.test" || ads[0].Type != Domain_Full {
		t.Fatalf("attr filter = %+v, want only ads.test", ads)
	}

	// Other entry code is reachable after the first entry is skipped.
	us, err := LoadGeoSiteLite(log, path, "us", "")
	if err != nil {
		t.Fatalf("second entry: %v", err)
	}
	if len(us) != 1 || us[0].Value != "us.test" {
		t.Fatalf("us entry = %+v", us)
	}

	if _, err = LoadGeoSiteLite(log, path, "jp", ""); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing code error = %v", err)
	}
}

func TestLoadGeoSiteLiteMatchesUnmarshal(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	list := &GeoSiteList{Entry: []*GeoSite{
		{CountryCode: "cn", Domain: []*Domain{
			{Type: Domain_Plain, Value: "a.test"},
			{Type: Domain_Full, Value: "b.test", Attribute: []*Domain_Attribute{{Key: "x"}}},
			{Type: Domain_Regex, Value: "c.test", Attribute: []*Domain_Attribute{{Key: "y"}}},
		}},
	}}
	path := writeGeoSiteList(t, list)

	for _, attr := range []string{"", "x", "X", "z"} {
		got, err := LoadGeoSiteLite(log, path, "cn", attr)
		if err != nil {
			t.Fatalf("lite attr=%q: %v", attr, err)
		}
		gs, err := UnmarshalGeoSite(log, path, "cn")
		if err != nil {
			t.Fatalf("unmarshal attr=%q: %v", attr, err)
		}
		var want []*Domain
		for _, item := range gs.Domain {
			hit := attr == ""
			for _, a := range item.Attribute {
				if strings.EqualFold(a.Key, attr) {
					hit = true
				}
			}
			if hit {
				want = append(want, item)
			}
		}
		if len(got) != len(want) {
			t.Fatalf("attr=%q: got %d domains, want %d", attr, len(got), len(want))
		}
		for i, d := range want {
			if got[i].Type != d.Type || got[i].Value != d.Value {
				t.Fatalf("attr=%q domain %d mismatch: got (%v,%q) want (%v,%q)",
					attr, i, got[i].Type, got[i].Value, d.Type, d.Value)
			}
		}
	}
}

func TestAppendGeoSiteEntryDomainsPreciseCapacity(t *testing.T) {
	list := &GeoSite{CountryCode: "cn", Domain: []*Domain{
		{Type: Domain_Full, Value: "a.test"},
		{Type: Domain_Plain, Value: "b.test"},
		{Type: Domain_RootDomain, Value: "c.test", Attribute: []*Domain_Attribute{{Key: "ads"}}},
	}}
	entry, err := proto.Marshal(list)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Without an attr filter every domain is kept, so the result must be
	// exactly sized: no growslice spare capacity.
	got, err := AppendGeoSiteEntryDomains(nil, entry, "")
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if len(got) != 3 || cap(got) != 3 {
		t.Fatalf("got len=%d cap=%d, want len=cap=3", len(got), cap(got))
	}
	if got[0].Value != "a.test" || got[1].Value != "b.test" || got[2].Value != "c.test" {
		t.Fatalf("zero-copy values mismatch: %q %q %q", got[0].Value, got[1].Value, got[2].Value)
	}

	// Attr filtering yields a shorter result but never an error.
	ads, err := AppendGeoSiteEntryDomains(nil, entry, "ads")
	if err != nil || len(ads) != 1 || ads[0].Value != "c.test" {
		t.Fatalf("attr filter: %+v err=%v", ads, err)
	}

	// Empty entry must canonicalize to a nil slice (no spurious allocation)
	// and parse without error.
	empty, err := AppendGeoSiteEntryDomains(nil, nil, "")
	if err != nil || len(empty) != 0 || empty != nil {
		t.Fatalf("empty entry = %v err=%v, want nil slice", empty, err)
	}

	// A caller-supplied dst is appended to and keeps working.
	withDst, err := AppendGeoSiteEntryDomains(make([]LiteDomain, 0, 8), entry, "")
	if err != nil || len(withDst) != 3 {
		t.Fatalf("with dst: len=%d err=%v", len(withDst), err)
	}
}

func TestGeoIPFallbackRejectsOversizedFile(t *testing.T) {
	path := t.TempDir() + "/oversized.dat"
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create fixture: %v", err)
	}
	if err = file.Truncate(maxGeoEntryLength + 1); err != nil {
		_ = file.Close()
		t.Fatalf("truncate fixture: %v", err)
	}
	if err = file.Close(); err != nil {
		t.Fatalf("close fixture: %v", err)
	}

	log := logrus.New()
	log.SetOutput(io.Discard)
	_, err = UnmarshalGeoIp(log, path, "CN")
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected oversized-file error, got %v", err)
	}
}
