package main

/*
 This program acts as an interface between the sysdig software
 written in C++ and container and orchestration systems. It's written
 in go to allow for the richer support ecosystem for
 containers/k8s/mesos/etc in go as compared to C++.
*/

import (
	"encoding/json"
	"flag"
	"fmt"
	log "github.com/cihub/seelog"
	"os"
        "github.com/draios/install_prefix"
	"cointerface/profile"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: cointerface [-sock=<path>] [-log_dir=<path>] [-modules_dir=<path>]\n")
	flag.PrintDefaults()
	os.Exit(1)
}

type LogMsg struct {
	Pid     int    `json:"pid"`
	Level   string `json:"level"`
	Message string `json:"message"`
}

func createJSONEscapeFormatter(params string) log.FormatterFunc {
	return func(message string, level log.LogLevel, context log.LogContextInterface) interface{} {
		bytes, err := json.Marshal(LogMsg{
			Pid:     os.Getpid(),
			Level:   level.String(),
			Message: message,
		})
		// Turn the json into jsonl by appending a newline
		endl := "\n"
		bytes = append(bytes, endl...)

		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not format log message: %s\n", err)
			return message
		}

		return string(bytes)
	}
}

//     <format id="agent-json" format="{&quot;pid&quot;: %d, &quot;level&quot;: &quot;%%Level&quot;, &quot;message&quot;: &quot;%%JSONEscapeMsg&quot;}"/>

func initLogging(useJson bool) {

	err := log.RegisterCustomFormatter("JSONEscapeMsg", createJSONEscapeFormatter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not create escaping formatter: %s", err)
		os.Exit(1)
	}

	config := `
<seelog>
  <formats>
    <format id="agent-plain" format="%Msg%n"/>
  </formats>
  <outputs>
    <console formatid="agent-plain"/>
  </outputs>
</seelog>
`
	if useJson {
		config = `
<seelog>
  <formats>
    <format id="agent-json" format="%JSONEscapeMsg"/>
  </formats>
  <outputs>
    <console formatid="agent-json"/>
  </outputs>
</seelog>
`
	}

	logger, err := log.LoggerFromConfigAsBytes([]byte(config))

	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not initialize logger: %s\n", err)
		os.Exit(1)
	}
	log.ReplaceLogger(logger)

}

var cpuProfile = flag.String("cpuprofile", "", "write cpu profile to `file`")
var eventsPerTrace = flag.Int("eventspertrace", 10000, "rollover the cpu profile ever N events")
var keepTraces = flag.Int("keeptraces", 30, "keep N cpu profiles")
var memProfile = flag.Bool("memprofile", false, "write mem profile to file")

func mymain() int {
	flag.Usage = usage
	prefix, err := install_prefix.GetInstallPrefix()
	if err != nil {
		log.Errorf("Could not determine installation directory: %s", err)
		return 1
	}
	sockPtr := flag.String("sock", prefix + "/run/cointerface.sock", "domain socket for messages")
	useJson := flag.Bool("use_json", true, "log using json")
	modulesDir := flag.String("modules_dir", prefix + "/lib/comp_modules", "compliance modules directory")

	flag.Parse()

	if *cpuProfile != "" {
		profile.ProgramStart(*cpuProfile, *eventsPerTrace, *keepTraces, *memProfile);
	}

	initLogging(*useJson)
	defer log.Flush()

	// Only returns when server is killed
	return startServer(*sockPtr, *modulesDir)
}

func main() {
	os.Exit(mymain())
}
