package main

import (
	"net/http"
	"runtime/debug"
	"time"
)

func init() {
	time.Local = time.FixedZone("CST", 8*3600)
	http.HandleFunc("/gc", func(w http.ResponseWriter, r *http.Request) {
		debug.FreeOSMemory()
		w.Write([]byte("done"))
	})
}
