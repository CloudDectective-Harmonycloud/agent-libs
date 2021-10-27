package profile

import (
	"fmt"
	"os"
	"runtime"
	"runtime/pprof"

	log "github.com/cihub/seelog"
)

var eventCount = 0
var traceCount = 0
var eventsPerTrace = 10000 // how many events we process before rolling the logfile
var tracesPerProfile = 30  // how many log files we write before overwriting the old ones
var logfileBase = ""
var profilingEnabled = false
var memProfileEnabled = false

func ProgramStart(filename string, eventspertrace int, keeptrace int, memprofile bool) {
	logfileBase = filename
	eventsPerTrace = eventspertrace
	tracesPerProfile = keeptrace
	memProfileEnabled = memprofile
	profilingEnabled = true

	logfile := fmt.Sprintf("%s.%d", filename, traceCount)

	f, err := os.Create(logfile)
	if err != nil {
		_ = log.Errorf("could not create CPU profile: %v", err)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		_ = log.Errorf("could not start CPU profile: %v", err)
	}
}

func NewEvent() {
	if !profilingEnabled {
		return
	}

	eventCount++
	if eventCount >= eventsPerTrace {

		// nuke the old CPU profile
		eventCount = 0
		pprof.StopCPUProfile()

		if memProfileEnabled {
			// cache the memory profile
			logfile := fmt.Sprintf("%s.%d.mem", logfileBase, traceCount)
			f, err := os.Create(logfile)
			if err != nil {
				_ = log.Errorf("could not create Mem profile: %v", err)
			}
			runtime.GC()
			if err := pprof.WriteHeapProfile(f); err != nil {
				_ = log.Errorf("could not write memory profile: %v", err)
			}
		}

		// start the new cpu profile
		traceCount++
		traceCount %= tracesPerProfile
		logfile := fmt.Sprintf("%s.%d", logfileBase, traceCount)

		f, err := os.Create(logfile)
		if err != nil {
			_ = log.Errorf("could not create CPU profile: %v", err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			_ = log.Errorf("could not start CPU profile: %v", err)
		}
	}
}
