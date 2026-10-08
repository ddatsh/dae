/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

// Modified from https://github.com/v2fly/v2ray-core/blob/42b166760b2ba8d984e514b830fcd44e23728e43/infra/conf/geodata/memconservative

package geodata

import (
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

func UnmarshalGeoIp(log *logrus.Logger, filepath, code string) (*GeoIP, error) {
	geoipBytes, err := Decode(filepath, code)
	switch err {
	case nil:
		var geoip GeoIP
		if err := proto.Unmarshal(geoipBytes, &geoip); err != nil {
			return nil, err
		}
		return &geoip, nil

	case errCodeNotFound:
		return nil, fmt.Errorf("country code %v not found in %v", code, filepath)

	case errFailedToReadBytes, errFailedToReadExpectedLenBytes,
		errInvalidGeodataFile, errInvalidGeodataVarintLength:
		if fi, statErr := os.Stat(filepath); statErr == nil && fi.Size() > maxGeoEntryLength {
			return nil, fmt.Errorf("geoip file %v is too large (%d bytes)", filepath, fi.Size())
		}
		log.Warnln("failed to decode geoip file: ", filepath, ", fallback to the original ReadFile method")
		geoipBytes, err = os.ReadFile(filepath)
		if err != nil {
			return nil, err
		}
		var geoipList GeoIPList
		if err := proto.Unmarshal(geoipBytes, &geoipList); err != nil {
			return nil, err
		}
		for _, geoip := range geoipList.GetEntry() {
			if strings.EqualFold(code, geoip.GetCountryCode()) {
				return geoip, nil
			}
		}

	default:
		return nil, err
	}

	return nil, fmt.Errorf("code %v not found in %v", code, filepath)
}

func UnmarshalGeoSite(log *logrus.Logger, filepath, code string) (*GeoSite, error) {
	geositeBytes, err := Decode(filepath, code)
	if err == nil {
		var geosite GeoSite
		if err := proto.Unmarshal(geositeBytes, &geosite); err != nil {
			return nil, err
		}
		return &geosite, nil
	}
	if err == errCodeNotFound {
		return nil, fmt.Errorf("code %v not found in %v", code, filepath)
	}
	return fallbackUnmarshalGeoSite(log, filepath, code, err)
}

// fallbackUnmarshalGeoSite keeps the legacy behavior for .dat files the
// incremental Decode cannot walk: if the file is small enough, read it whole
// and scan the GeoSiteList linearly.
func fallbackUnmarshalGeoSite(log *logrus.Logger, filepath, code string, decodeErr error) (*GeoSite, error) {
	switch decodeErr {
	case errFailedToReadBytes, errFailedToReadExpectedLenBytes,
		errInvalidGeodataFile, errInvalidGeodataVarintLength:
		if fi, statErr := os.Stat(filepath); statErr == nil && fi.Size() > maxGeoEntryLength {
			return nil, fmt.Errorf("geosite file %v is too large (%d bytes)", filepath, fi.Size())
		}
		log.Warnln("failed to decode geosite file: ", filepath, ", fallback to the original ReadFile method")
		geositeBytes, err := os.ReadFile(filepath)
		if err != nil {
			return nil, err
		}
		var geositeList GeoSiteList
		if err := proto.Unmarshal(geositeBytes, &geositeList); err != nil {
			return nil, err
		}
		for _, geosite := range geositeList.GetEntry() {
			if strings.EqualFold(code, geosite.GetCountryCode()) {
				return geosite, nil
			}
		}
		return nil, fmt.Errorf("code %v not found in %v", code, filepath)
	default:
		return nil, decodeErr
	}
}

// domainHasAttr reports whether the domain carries attr as one of its
// attribute keys (case-insensitive). An empty attr matches every domain.
func domainHasAttr(item *Domain, attr string) bool {
	if attr == "" {
		return true
	}
	for _, itemAttr := range item.Attribute {
		if strings.EqualFold(itemAttr.Key, attr) {
			return true
		}
	}
	return false
}

// LoadGeoSiteLite extracts the domains of one GeoSite code without building
// the protobuf object tree: the matched entry bytes are walked directly. For
// large geosite files (hundreds of thousands of Domain messages) proto.Unmarshal
// used to allocate the entire message/attribute graph plus a repeatedly
// growing domain slice, which was the dominant allocation and GC driver
// during routing rule build.
func LoadGeoSiteLite(log *logrus.Logger, filepath, code, attr string) ([]LiteDomain, error) {
	entry, err := Decode(filepath, code)
	if err == nil {
		return AppendGeoSiteEntryDomains(nil, entry, attr)
	}
	if err == errCodeNotFound {
		return nil, fmt.Errorf("code %v not found in %v", code, filepath)
	}
	// Keep the legacy whole-file fallback for files Decode cannot walk.
	geoSite, err := fallbackUnmarshalGeoSite(log, filepath, code, err)
	if err != nil {
		return nil, err
	}
	var domains []LiteDomain
	for _, item := range geoSite.Domain {
		if !domainHasAttr(item, attr) {
			continue
		}
		domains = append(domains, LiteDomain{Type: item.Type, Value: item.Value})
	}
	return domains, nil
}
