package prof

import (
    "os"
    "runtime/pprof"
)

var f *os.File
var count = 0

func Start() {
	var err error
	count++
	f, err = os.Create("/tmp/cpu.prof")
	if err != nil {
		panic(err)
	}
	err = pprof.StartCPUProfile(f)
	if err != nil {
		panic(err)
	}
}

func Stop() {
	pprof.StopCPUProfile()
	_ = f.Close()
}
