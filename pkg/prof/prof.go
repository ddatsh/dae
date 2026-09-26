package prof

import (
    "os"
    "runtime/pprof"
    "time"
)

var f *os.File
var count = 0

var startTime = time.Now()

func StartTime() time.Time {
	return startTime
}

func ResetTime() {
	startTime = time.Now()
}

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
