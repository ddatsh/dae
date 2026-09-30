//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package main

import (
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/daeuniverse/dae/cmd"
	"github.com/daeuniverse/dae/common/json"
	"github.com/daeuniverse/dae/pkg/cache"
	"github.com/daeuniverse/dae/pkg/prof"
	jsoniter "github.com/json-iterator/go"
	"github.com/json-iterator/go/extra"
)

func main() {

	time.Local = time.FixedZone("CST", 8*3600)
	http.HandleFunc("/gc", func(w http.ResponseWriter, r *http.Request) {
		runtime.GC()
		w.Write([]byte("done"))
	})
	http.HandleFunc("/init", func(w http.ResponseWriter, r *http.Request) {
		cache.DoInit()
		w.Write([]byte("done"))
	})
	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)
	prof.Start()
	jsoniter.RegisterTypeDecoder("bool", &json.FuzzyBoolDecoder{})
	extra.RegisterFuzzyDecoders()

	http.DefaultClient.Timeout = 30 * time.Second
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
