package control

import (
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/pkg/cache"
	"github.com/mgutz/ansi"
	"github.com/sirupsen/logrus"
)

// dnsTraceMergeWindow coalesces dns:hit/dns:reject trace lines for the same
// domain that arrive within the window (browsers fire A/AAAA/HTTPS together)
// into a single "name(A,AAAA,HTTPS)" line.
const dnsTraceMergeWindow = 1 * time.Second

// dnsTraceKey identifies the log group: lines are merged only when every
// identity field matches.
type dnsTraceKey struct {
	prefix   string // colored log prefix, e.g. ansi.Color("dns:hit", "black+h")
	qname    string
	upstream string // "upstream" field, empty if absent
	field    string // source field name: "source" (hit) or "src" (reject)
	source   string
}

type dnsTraceEntry struct {
	qtypes []string
}

var (
	dnsTraceMu  sync.Mutex
	dnsTraceMap = make(map[dnsTraceKey]*dnsTraceEntry)
)

// mergeDnsTrace buffers qtype under key and flushes all collected qtypes as
// one "name(T1,T2,...)" line after dnsTraceMergeWindow. Callers keep their
// own per-(qname,qtype) dedup and level gating.
func mergeDnsTrace(log *logrus.Logger, key dnsTraceKey, qtype string) {
	dnsTraceMu.Lock()
	defer dnsTraceMu.Unlock()
	entry, ok := dnsTraceMap[key]
	if !ok {
		entry = &dnsTraceEntry{}
		dnsTraceMap[key] = entry
		time.AfterFunc(dnsTraceMergeWindow, func() { flushDnsTrace(log, key) })
	}
	for _, t := range entry.qtypes {
		if t == qtype {
			return
		}
	}
	entry.qtypes = append(entry.qtypes, qtype)
}

func flushDnsTrace(log *logrus.Logger, key dnsTraceKey) {
	dnsTraceMu.Lock()
	entry, ok := dnsTraceMap[key]
	delete(dnsTraceMap, key)
	dnsTraceMu.Unlock()
	if !ok || len(entry.qtypes) == 0 {
		return
	}
	l := log.WithField("prefix", key.prefix)
	if key.upstream != "" {
		l = l.WithField("upstream", key.upstream)
	}
	if key.field != "" && key.source != "" {
		l = l.WithField(key.field, key.source)
	}
	l.Trace(key.qname + "(" + strings.Join(entry.qtypes, ",") + ")")
}

// traceDnsHit emits a merged "dns:hit name(T1,T2,...)" trace line. Hits for
// the same domain sharing source and upstream inside dnsTraceMergeWindow are
// coalesced into one line; cache.NotExistsWithTTL still keeps repeated hits
// quiet for 10s.
func traceDnsHit(log *logrus.Logger, name, qtype, source, upstream string) {
	qname := strings.TrimSuffix(name, ".")
	if !cache.NotExistsWithTTL(qname+qtype, 10*time.Second) {
		return
	}
	mergeDnsTrace(log, dnsTraceKey{
		prefix:   ansi.Color("dns:hit", "black+h"),
		qname:    qname,
		upstream: upstream,
		field:    "source",
		source:   source,
	}, qtype)
}
