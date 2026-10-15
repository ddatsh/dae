package main

import (
	"net/http"
	"runtime/debug"
	"time"

	"github.com/daeuniverse/dae/control"
)

func init() {
	time.Local = time.FixedZone("CST", 8*3600)
	http.HandleFunc("/gc", func(w http.ResponseWriter, r *http.Request) {
		debug.FreeOSMemory()
		w.Write([]byte("done"))
	})
	http.HandleFunc("/live", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		control.WriteLiveFlows(w)
	})
}
