// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

// Package limiter slows down repeated failures per key with exponential backoff.
package limiter

import (
	"sync"
	"time"
)

type entry struct {
	fails int
	until time.Time
	last  time.Time
}

type Limiter struct {
	mu     sync.Mutex
	m      map[string]*entry
	free   int           // failures allowed before locking
	max    time.Duration // longest lockout
	expire time.Duration // forget a key after this long without failures
}

func New(free int, max, expire time.Duration) *Limiter {
	return &Limiter{m: map[string]*entry{}, free: free, max: max, expire: expire}
}

// Allow reports whether key may try now, and otherwise how long to wait.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gc()
	e := l.m[key]
	if e == nil {
		return true, 0
	}
	if d := time.Until(e.until); d > 0 {
		return false, d
	}
	return true, 0
}

func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.m[key]
	if e == nil {
		e = &entry{}
		l.m[key] = e
	}
	e.fails++
	e.last = time.Now()
	if over := e.fails - l.free; over > 0 {
		d := time.Second << min(over-1, 16)
		if d > l.max {
			d = l.max
		}
		e.until = time.Now().Add(d)
	}
}

func (l *Limiter) Success(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}

func (l *Limiter) gc() {
	if len(l.m) < 1024 {
		return
	}
	for k, e := range l.m {
		if time.Since(e.last) > l.expire {
			delete(l.m, k)
		}
	}
}

// Login throttles by three keys so one attacker cannot lock others out:
// the (ip, user) pair is strict, the ip alone catches password spraying over
// many names, and the user alone is a soft cap against distributed guessing.
type Login struct {
	pair, host, user *Limiter
}

func NewLogin() *Login {
	return &Login{
		pair: New(3, 5*time.Minute, time.Hour),
		host: New(15, 5*time.Minute, time.Hour),
		user: New(20, time.Minute, time.Hour),
	}
}

func (l *Login) Allow(ip, user string) (bool, time.Duration) {
	var wait time.Duration
	ok := true
	for _, c := range []struct {
		l *Limiter
		k string
	}{{l.pair, ip + "|" + user}, {l.host, ip}, {l.user, user}} {
		if a, d := c.l.Allow(c.k); !a {
			ok, wait = false, max(wait, d)
		}
	}
	return ok, wait
}

func (l *Login) Fail(ip, user string) {
	l.pair.Fail(ip + "|" + user)
	l.host.Fail(ip)
	l.user.Fail(user)
}

// Success clears only the pair: a correct password from one place must not
// reset the counters an attacker is building up elsewhere.
func (l *Login) Success(ip, user string) { l.pair.Success(ip + "|" + user) }
