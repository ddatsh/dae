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

func UnmarshalGeoSite(_ *logrus.Logger, filepath, code string) (*GeoSite, error) {
	geositeBytes, err := Decode(filepath, code)
	if err == nil {
		var geosite GeoSite
		if err := proto.Unmarshal(geositeBytes, &geosite); err != nil {
			return nil, err
		}
		return &geosite, nil
	}

	return nil, fmt.Errorf("code %v not found in %v", code, filepath)

}

// LoadGeoSiteLite extracts the domains of one GeoSite code without building
// the protobuf object tree: the matched entry bytes are walked directly. For
// large geosite files (hundreds of thousands of Domain messages) proto.Unmarshal
// used to allocate the entire message/attribute graph plus a repeatedly
// growing domain slice, which was the dominant allocation and GC driver
// during routing rule build.
func LoadGeoSiteLite(_ *logrus.Logger, filepath, code, attr string) ([]LiteDomain, error) {
	entry, err := Decode(filepath, code)
	if err == nil {
		return AppendGeoSiteEntryDomains(nil, entry, attr)
	}

	return nil, fmt.Errorf("code %v not found in %v", code, filepath)

}
