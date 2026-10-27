// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/btdt1983/cerberusttpd/internal/ipc"
)

const (
	cookieName  = "__Host-cerb_sess"
	idleTimeout = 30 * time.Minute
	maxLife     = 12 * time.Hour
	pendingLife = 5 * time.Minute // time allowed to finish the second factor
)

// Stage is how far a session got through login. Phase 5 adds the TOTP step
// between StagePassword and StageFull; only StageFull may access files.
type Stage int

const (
	StagePassword Stage = iota + 1
	StageFull
)

type Session struct {
	User    string
	UID     uint32
	Admin   bool
	Stage   Stage
	Created time.Time
	seen    time.Time
	worker  *ipc.Client // nil until the second factor is done

	Pending string // helper's token for a login waiting on its second factor
	MFAMode string // "verify" or "enroll"
	uri     string // otpauth:// URI while enrolling

	streams atomic.Int32
}

func (s *Session) close() {
	if s.worker != nil {
		s.worker.Close()
	}
}

type sessions struct {
	mu sync.Mutex
	m  map[[32]byte]*Session
}

func newSessions() *sessions { return &sessions{m: map[[32]byte]*Session{}} }

// create stores s under a fresh 256-bit token; only its hash is kept.
func (ss *sessions) create(s *Session) (string, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	s.Created = time.Now()
	s.seen = s.Created
	ss.mu.Lock()
	ss.m[sha256.Sum256(raw[:])] = s
	ss.mu.Unlock()
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func key(token string) ([32]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 32 {
		return [32]byte{}, false
	}
	return sha256.Sum256(raw), true
}

// get returns the live session for token and refreshes its idle timer.
func (ss *sessions) get(token string) *Session {
	k, ok := key(token)
	if !ok {
		return nil
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s := ss.m[k]
	if s == nil {
		return nil
	}
	if expired(s, time.Now()) {
		delete(ss.m, k)
		s.close()
		return nil
	}
	s.seen = time.Now()
	return s
}

func (ss *sessions) destroy(token string) {
	k, ok := key(token)
	if !ok {
		return
	}
	ss.mu.Lock()
	s := ss.m[k]
	delete(ss.m, k)
	ss.mu.Unlock()
	if s != nil {
		s.close()
	}
}

func (ss *sessions) reap() {
	now := time.Now()
	ss.mu.Lock()
	defer ss.mu.Unlock()
	for k, s := range ss.m {
		if expired(s, now) {
			delete(ss.m, k)
			s.close()
		}
	}
}

func expired(s *Session, now time.Time) bool {
	if s.Stage < StageFull && now.Sub(s.Created) > pendingLife {
		return true
	}
	return now.Sub(s.seen) > idleTimeout || now.Sub(s.Created) > maxLife
}

// promote swaps the pending session behind oldToken for full under a fresh
// token, so the token that existed before 2FA is worthless afterwards.
func (ss *sessions) promote(oldToken string, full *Session) (string, error) {
	ss.destroyNoClose(oldToken)
	return ss.create(full)
}

func (ss *sessions) destroyNoClose(token string) {
	if k, ok := key(token); ok {
		ss.mu.Lock()
		delete(ss.m, k)
		ss.mu.Unlock()
	}
}

// peek returns the live full session for token without refreshing its idle
// timer, so a page left open cannot keep a session alive.
func (ss *sessions) peek(token string) *Session {
	k, ok := key(token)
	if !ok {
		return nil
	}
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s := ss.m[k]
	if s == nil || s.Stage < StageFull || expired(s, time.Now()) {
		return nil
	}
	return s
}

// presence summarises who is logged in, one entry per user.
func (ss *sessions) presence(now time.Time) []userStat {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	by := map[string]*userStat{}
	for _, s := range ss.m {
		if s.Stage < StageFull || expired(s, now) {
			continue
		}
		u := by[s.User]
		if u == nil {
			u = &userStat{Name: s.User, Admin: s.Admin, Idle: -1}
			by[s.User] = u
		}
		u.Sessions++
		if idle := int(now.Sub(s.seen).Seconds()); u.Idle < 0 || idle < u.Idle {
			u.Idle = idle
		}
	}
	out := make([]userStat, 0, len(by))
	for _, u := range by {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
