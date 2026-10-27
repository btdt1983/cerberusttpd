// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btdt1983/cerberusttpd/internal/worker"
)

const (
	histLen    = 120 // seconds of history sent to a new viewer
	maxStreams = 256
)

type userStat struct {
	Name     string `json:"name"`
	Admin    bool   `json:"admin"`
	Sessions int    `json:"sessions"`
	Idle     int    `json:"idle"` // seconds since last request
}

type snapshot struct {
	T         int64      `json:"t"`
	In        float64    `json:"in"`  // bytes/s uploaded to the server
	Out       float64    `json:"out"` // bytes/s downloaded from the server
	TotalIn   int64      `json:"totalIn"`
	TotalOut  int64      `json:"totalOut"`
	CPU       float64    `json:"cpu"` // percent busy
	MemUsed   uint64     `json:"memUsed"`
	MemTotal  uint64     `json:"memTotal"`
	Load      [3]float64 `json:"load"`
	Cores     int        `json:"cores"`
	Uptime    int64      `json:"uptime"`
	Transfers int32      `json:"transfers"`
	Users     []userStat `json:"users"`
}

// stats counts the bytes the server reads and writes on its sockets (see
// wire.go: TLS, QUIC and HTTP headers included) and samples the machine once
// a second. Everything a viewer sees comes from one shared sample.
type stats struct {
	in, out  atomic.Int64
	inflight atomic.Int32
	streams  atomic.Int32

	mu     sync.RWMutex
	latest []byte
	hist   []snapshot
}

func (st *stats) run(ss *sessions) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var lastIn, lastOut int64
	last := time.Now()
	var prevBusy, prevTotal uint64
	for now := range tick.C {
		el := now.Sub(last).Seconds()
		last = now
		in, out := st.in.Load(), st.out.Load()
		snap := snapshot{
			T: now.UnixMilli(), In: float64(in-lastIn) / el, Out: float64(out-lastOut) / el,
			TotalIn: in, TotalOut: out, Cores: runtime.NumCPU(), Transfers: st.inflight.Load(),
		}
		lastIn, lastOut = in, out
		busy, total := cpuTimes()
		if total > prevTotal {
			snap.CPU = 100 * float64(busy-prevBusy) / float64(total-prevTotal)
		}
		prevBusy, prevTotal = busy, total
		snap.MemUsed, snap.MemTotal = memInfo()
		snap.Load = loadAvg()
		snap.Uptime = uptime()
		snap.Users = ss.presence(now)
		b, _ := json.Marshal(snap)
		st.mu.Lock()
		st.latest = b
		st.hist = append(st.hist, snap)
		if len(st.hist) > histLen {
			st.hist = st.hist[len(st.hist)-histLen:]
		}
		st.mu.Unlock()
	}
}

func (st *stats) snapshotJSON() ([]byte, []snapshot) {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.latest, append([]snapshot(nil), st.hist...)
}

// /proc readers: the network process is unprivileged but /proc/stat, meminfo
// and loadavg are world-readable.

func cpuTimes() (busy, total uint64) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	line, _ := bufio.NewReader(f).ReadString('\n')
	fields := strings.Fields(line)
	if len(fields) < 8 || fields[0] != "cpu" {
		return 0, 0
	}
	var v [8]uint64
	for i := range v {
		v[i], _ = strconv.ParseUint(fields[i+1], 10, 64)
		total += v[i]
	}
	return total - v[3] - v[4], total // minus idle and iowait
}

func memInfo() (used, total uint64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	var avail uint64
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		kb, _ := strconv.ParseUint(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			total = kb * 1024
		case "MemAvailable:":
			avail = kb * 1024
		}
	}
	if avail > total {
		avail = total
	}
	return total - avail, total
}

func loadAvg() (l [3]float64) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return
	}
	f := strings.Fields(string(b))
	for i := 0; i < 3 && i < len(f); i++ {
		l[i], _ = strconv.ParseFloat(f[i], 64)
	}
	return
}

func uptime() int64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f, _ := strconv.ParseFloat(strings.Fields(string(b))[0], 64)
	return int64(f)
}

// track marks a file transfer as in flight until the returned func is called.
func (s *Server) track(r *http.Request) func() {
	transfer := (r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/files/") && !strings.HasSuffix(r.URL.Path, "/")) ||
		(r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/tus/"))
	if !transfer {
		return func() {}
	}
	s.stats.inflight.Add(1)
	return func() { s.stats.inflight.Add(-1) }
}

// statsStream is the live feed behind the sidebar (Server-Sent Events).
func (s *Server) statsStream(w http.ResponseWriter, r *http.Request) {
	// peek, not current: connecting must not refresh the idle timer, or an
	// open page (whose stream reconnects by itself) would never log out.
	token := cookieValue(r)
	sess := s.sess.peek(token)
	if sess == nil {
		http.Error(w, "not signed in", http.StatusUnauthorized)
		return
	}
	if s.stats.streams.Load() >= maxStreams || sess.streams.Load() >= 6 {
		http.Error(w, "too many open connections", http.StatusTooManyRequests)
		return
	}
	s.stats.streams.Add(1)
	sess.streams.Add(1)
	defer func() { s.stats.streams.Add(-1); sess.streams.Add(-1) }()

	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	send := func(event string, data []byte) bool {
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	disk := func() []byte {
		var resp worker.Response
		if _, err := sess.worker.Call(worker.Request{Op: "statfs"}, &resp); err != nil || resp.Err != "" {
			return nil
		}
		b, _ := json.Marshal(map[string]int64{"total": resp.Total, "avail": resp.Avail})
		return b
	}

	_, hist := s.stats.snapshotJSON()
	hello, _ := json.Marshal(map[string]any{"me": sess.User, "hist": hist})
	if !send("hello", hello) {
		return
	}
	if d := disk(); d != nil {
		send("disk", d)
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var lastT string
	n := 0
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.done:
			return
		case <-tick.C:
		}
		if s.sess.peek(token) == nil {
			send("bye", []byte("{}"))
			return
		}
		latest, _ := s.stats.snapshotJSON()
		if latest != nil && string(latest[:min(len(latest), 24)]) != lastT {
			lastT = string(latest[:min(len(latest), 24)])
			if !send("stats", latest) {
				return
			}
		}
		if n++; n%15 == 0 {
			if d := disk(); d != nil && !send("disk", d) {
				return
			}
		}
	}
}
