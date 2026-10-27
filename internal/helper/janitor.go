// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const (
	cleanupEvery = 24 * time.Hour
	forgetAfter  = 90 * 24 * time.Hour
	cleanupLimit = 15 * time.Minute
)

func (s *server) seenPath() string { return filepath.Join(s.DataDir, "users.json") }

// noteSeen remembers who has logged in, so abandoned uploads of people who
// stopped coming back still get cleaned.
func (s *server) noteSeen(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = map[string]time.Time{}
	}
	s.seen[name] = time.Now()
	s.saveSeenLocked()
}

func (s *server) saveSeenLocked() {
	b, err := json.Marshal(s.seen)
	if err != nil {
		return
	}
	tmp := s.seenPath() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		os.Rename(tmp, s.seenPath())
	}
}

func (s *server) loadSeen() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seen = map[string]time.Time{}
	if b, err := os.ReadFile(s.seenPath()); err == nil {
		json.Unmarshal(b, &s.seen)
	}
}

// janitor drops expired pending logins every minute and runs the upload
// cleanup per known user once a day.
func (s *server) janitor() {
	s.loadSeen()
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	next := time.Now().Add(2 * time.Minute)
	for now := range tick.C {
		s.mu.Lock()
		for k, p := range s.pending {
			if now.After(p.expires) {
				delete(s.pending, k)
			}
		}
		s.mu.Unlock()
		if s.StaleAfter > 0 && now.After(next) {
			next = now.Add(cleanupEvery)
			s.cleanupAll()
		}
	}
}

func (s *server) cleanupAll() {
	s.mu.Lock()
	var names []string
	for n, t := range s.seen {
		if time.Since(t) > forgetAfter {
			delete(s.seen, n)
			continue
		}
		names = append(names, n)
	}
	s.saveSeenLocked()
	s.mu.Unlock()
	for _, n := range names {
		u, err := user.Lookup(n)
		if err != nil {
			continue
		}
		s.cleanupUser(u)
	}
}

// cleanupUser runs `cleanup` with u's credentials, so deletion rights are the user's own.
func (s *server) cleanupUser(u *user.User) {
	cred, _, err := credFor(u)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), cleanupLimit)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.Exe, "cleanup", s.rootFor(u), strconv.Itoa(int(s.StaleAfter.Seconds())))
	cmd.Dir = "/"
	cmd.Env = []string{}
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	if err := cmd.Run(); err != nil {
		log.Printf("helper: cleanup for %q: %v", u.Username, err)
	}
}
