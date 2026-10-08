/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

// Modified from https://github.com/v2fly/v2ray-core/blob/42b166760b2ba8d984e514b830fcd44e23728e43/infra/conf/geodata/memconservative

package geodata

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unsafe"

	"google.golang.org/protobuf/encoding/protowire"
)

var (
	errFailedToReadBytes            = errors.New("failed to read bytes")
	errFailedToReadExpectedLenBytes = errors.New("failed to read expected length of bytes")
	errInvalidGeodataFile           = errors.New("invalid geodata file")
	errInvalidGeodataVarintLength   = errors.New("invalid geodata varint length")
	errCodeNotFound                 = errors.New("code not found")
)

// maxGeoEntryLength bounds a single varint-declared record length so that a
// corrupted or hostile .dat file cannot request a huge allocation.
const maxGeoEntryLength = 1 << 28 // 256 MiB

func emitBytes(f io.ReadSeeker, code string) ([]byte, error) {
	count := 1
	isInner := false
	tempContainer := make([]byte, 0, 5)

	var result []byte
	var advancedN uint64 = 1
	var geoDataVarintLength, codeVarintLength, varintLenByteLen uint64 = 0, 0, 0

Loop:
	for {
		container := make([]byte, advancedN)
		bytesRead, err := f.Read(container)
		if err == io.EOF {
			if len(tempContainer) != 0 {
				return nil, errInvalidGeodataVarintLength
			}
			return nil, errCodeNotFound
		}
		if err != nil {
			return nil, errFailedToReadBytes
		}
		if bytesRead != len(container) {
			return nil, errFailedToReadExpectedLenBytes
		}

		switch count {
		case 1, 3: // data type ((field_number << 3) | wire_type)
			if container[0] != 10 { // byte `0A` equals to `10` in decimal
				return nil, errInvalidGeodataFile
			}
			advancedN = 1
			count++
		case 2, 4: // data length
			tempContainer = append(tempContainer, container...)
			if len(tempContainer) > binary.MaxVarintLen64 {
				return nil, errInvalidGeodataVarintLength
			}
			if container[0] > 127 { // max one-byte-length byte `7F`(0FFF FFFF) equals to `127` in decimal
				advancedN = 1
				goto Loop
			}
			lenVarint, n := protowire.ConsumeVarint(tempContainer)
			if n < 0 {
				return nil, errInvalidGeodataVarintLength
			}
			tempContainer = nil
			if !isInner {
				isInner = true
				geoDataVarintLength = lenVarint
				if geoDataVarintLength > maxGeoEntryLength {
					return nil, errInvalidGeodataVarintLength
				}
				advancedN = 1
			} else {
				isInner = false
				codeVarintLength = lenVarint
				if codeVarintLength > maxGeoEntryLength {
					return nil, errInvalidGeodataVarintLength
				}
				varintLenByteLen = uint64(n)
				advancedN = codeVarintLength
			}
			count++
		case 5: // data value
			if strings.EqualFold(string(container), code) {
				count++
				offset := -(1 + int64(varintLenByteLen) + int64(codeVarintLength))
				_, _ = f.Seek(offset, 1)        // back to the start of GeoIP or GeoSite varint
				advancedN = geoDataVarintLength // the number of bytes to be read in next round
			} else {
				count = 1
				offset := int64(geoDataVarintLength) - int64(codeVarintLength) - int64(varintLenByteLen) - 1
				_, _ = f.Seek(offset, 1) // skip the unmatched GeoIP or GeoSite varint
				advancedN = 1            // the next round will be the start of another GeoIPList or GeoSiteList
			}
		case 6: // matched GeoIP or GeoSite varint
			result = container
			break Loop
		}
	}
	return result, nil
}

func Decode(filename, code string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v: %w", filename, err)
	}
	defer func() { _ = f.Close() }()

	geoBytes, err := emitBytes(f, code)
	if err != nil {
		return nil, err
	}
	return geoBytes, nil
}

// LiteDomain is a heap-cheap view of one GeoSite domain entry, produced by
// direct wire-format parsing without allocating the protobuf message and
// attribute object tree.
type LiteDomain struct {
	Type  Domain_Type
	Value string
}

// AppendGeoSiteEntryDomains walks one serialized GeoSite entry and appends
// its domains to dst. attr, when non-empty, keeps only domains carrying an
// attribute whose key equals attr (case-insensitively), matching the
// code@attr semantics applied on top of proto.Unmarshal.
//
// The GeoSite layout is:
//
//	1: country_code (string)
//	2: domain        (repeated Domain message)
//
// Domain is:
//
//	1: type      (varint)
//	2: value     (string)
//	3: attribute (repeated Domain_Attribute message; key is field 1)
//
// Any other field is skipped, so forward-compatible files still parse.
//
// The returned LiteDomain values share entry's backing byte array (their
// Value strings are zero-copy views into it), so callers must not mutate
// entry for as long as the results are reachable. entry is a freshly read
// decode buffer that is never written to or exposed, so this is safe and
// keeps its bytes alive through the string headers.
func AppendGeoSiteEntryDomains(dst []LiteDomain, entry []byte, attr string) ([]LiteDomain, error) {
	if cap(dst)-len(dst) == 0 {
		// Reserve exact capacity with one allocation. Appending into a nil
		// slice one domain at a time grows it ~log2(N) times: every growth
		// re-copies the existing LiteDomain values (each carries a string
		// pointer) under GC write barriers, which dominated this decode in
		// CPU profiles (runtime.growslice).
		if count, ok := countGeoSiteEntryDomains(entry); ok && count > 0 {
			grown := make([]LiteDomain, len(dst), len(dst)+count)
			copy(grown, dst)
			dst = grown
		}
	}
	var attrBytes []byte
	if attr != "" {
		attrBytes = []byte(attr)
	}
	for len(entry) > 0 {
		fieldNum, wireType, n := protowire.ConsumeTag(entry)
		if n < 0 {
			return nil, protowire.ParseError(n)
		}
		entry = entry[n:]
		if fieldNum == 2 && wireType == protowire.BytesType {
			domain, m := protowire.ConsumeBytes(entry)
			if m < 0 {
				return nil, protowire.ParseError(m)
			}
			entry = entry[m:]
			dst = appendLiteDomain(dst, domain, attrBytes)
			continue
		}
		m := protowire.ConsumeFieldValue(fieldNum, wireType, entry)
		if m < 0 {
			return nil, protowire.ParseError(m)
		}
		entry = entry[m:]
	}
	return dst, nil
}

// countGeoSiteEntryDomains counts top-level field-2 (Domain) messages in a
// serialized GeoSite entry without descending into them. A failed scan
// returns ok=false so the caller can fall back to plain append growth (the
// second, strict pass then surfaces the parse error).
func countGeoSiteEntryDomains(entry []byte) (count int, ok bool) {
	for len(entry) > 0 {
		fieldNum, wireType, n := protowire.ConsumeTag(entry)
		if n < 0 {
			return count, false
		}
		entry = entry[n:]
		if fieldNum == 2 && wireType == protowire.BytesType {
			count++
		}
		m := protowire.ConsumeFieldValue(fieldNum, wireType, entry)
		if m < 0 {
			return count, false
		}
		entry = entry[m:]
	}
	return count, true
}

func appendLiteDomain(dst []LiteDomain, b []byte, attr []byte) []LiteDomain {
	var d LiteDomain
	// attrHit is pre-set when no attribute filter is requested.
	attrHit := len(attr) == 0
	for len(b) > 0 {
		fieldNum, wireType, n := protowire.ConsumeTag(b)
		if n < 0 {
			// Malformed domain: stop here and keep what was parsed.
			return dst
		}
		b = b[n:]
		switch {
		case fieldNum == 1 && wireType == protowire.VarintType:
			v, m := protowire.ConsumeVarint(b)
			if m < 0 {
				return dst
			}
			b = b[m:]
			d.Type = Domain_Type(int32(v))
		case fieldNum == 2 && wireType == protowire.BytesType:
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return dst
			}
			b = b[m:]
			// Zero-copy view over the entry buffer: protowire.ConsumeString
			// would do string(v), one heap allocation and copy per domain.
			d.Value = bytesString(v)
		case fieldNum == 3 && wireType == protowire.BytesType:
			msg, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return dst
			}
			b = b[m:]
			if !attrHit && attributeHasKey(msg, attr) {
				attrHit = true
			}
		default:
			m := protowire.ConsumeFieldValue(fieldNum, wireType, b)
			if m < 0 {
				return dst
			}
			b = b[m:]
		}
	}
	if attrHit {
		dst = append(dst, d)
	}
	return dst
}

// bytesString reinterprets b as a string without copying. The caller must
// guarantee b's backing memory is never mutated afterwards; here it always
// points into the immutable decode buffer of one GeoSite entry.
func bytesString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

// attributeHasKey reports whether a serialized Domain_Attribute carries key
// as its field-1 string (case-insensitive). Other attribute fields are
// skipped. It works on byte slices to avoid allocating a string per
// attribute.
func attributeHasKey(b []byte, key []byte) bool {
	for len(b) > 0 {
		fieldNum, wireType, n := protowire.ConsumeTag(b)
		if n < 0 {
			return false
		}
		b = b[n:]
		if fieldNum == 1 && wireType == protowire.BytesType {
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return false
			}
			if bytes.EqualFold(v, key) {
				return true
			}
			b = b[m:]
			continue
		}
		m := protowire.ConsumeFieldValue(fieldNum, wireType, b)
		if m < 0 {
			return false
		}
		b = b[m:]
	}
	return false
}
