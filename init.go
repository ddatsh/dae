package main

import (
	"net/http"
	"runtime/debug"
	"time"

	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/cache"
)

func init() {
	time.Local = time.FixedZone("CST", 8*3600)
	http.HandleFunc("/gc", func(w http.ResponseWriter, r *http.Request) {
		debug.FreeOSMemory()
		w.Write([]byte("done"))
	})
	http.HandleFunc("/init", func(w http.ResponseWriter, r *http.Request) {
		cache.DoInit()
		w.Write([]byte("done"))
	})
	http.HandleFunc("/live", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		control.WriteLiveFlows(w)
	})
}
