package services

import (
	"encoding/json"
	"fmt"
	"runtime"
	"time"
)

type Monitor struct {
	Alloc,
	TotalAlloc,
	Sys,
	Mallocs,
	Frees,
	LiveObjects,
	PauseTotalNs uint64

	NumGC        uint32
	NumGoroutine int

	NumCPUs uint32

	// MQTT
	AckMessages    int
	UnAckMessages  int
	CachedMessages int

	UpTime uint64
}

func NewMonitor(duration int) {
	var m Monitor
	var rtm runtime.MemStats
	interval := time.Duration(duration) * time.Second
	startTime := time.Now()
	for {
		<-time.After(interval)

		// Read full mem stats
		runtime.ReadMemStats(&rtm)

		// Number of goroutines
		m.NumGoroutine = runtime.NumGoroutine()

		// Misc memory stats
		m.Alloc = rtm.Alloc
		m.TotalAlloc = rtm.TotalAlloc
		m.Sys = rtm.Sys
		m.Mallocs = rtm.Mallocs
		m.Frees = rtm.Frees

		// Live objects = Mallocs - Frees
		m.LiveObjects = m.Mallocs - m.Frees

		// GC Stats
		m.PauseTotalNs = rtm.PauseTotalNs
		m.NumGC = rtm.NumGC

		// Number of CPUs
		m.NumCPUs = uint32(runtime.NumCPU())

		// Uptime
		m.UpTime = uint64(time.Since(startTime).Seconds())

		m.AckMessages = AckMessages
		m.UnAckMessages = UnAckMessages
		m.CachedMessages = CachedMessages

		// Just encode to json and print
		b, _ := json.Marshal(m)
		fmt.Println(string(b))
	}
}
