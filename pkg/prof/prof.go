package prof

import (
    "os"
    "runtime"
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
	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)

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
	runtime.SetBlockProfileRate(0)
	runtime.SetMutexProfileFraction(0)
	_ = f.Close()
}
