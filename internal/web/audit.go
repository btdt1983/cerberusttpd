// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ringSize is how many recent events the admin page can show. They also
// go to the journal, which stays the complete record; this copy is only
// for a quick look and is gone after a restart.
const ringSize = 2000

type auditEvent struct {
	Time                                  time.Time
	Event, User, IP, Auth, Result, Detail string
}

type auditRing struct {
	mu   sync.Mutex
	buf  []auditEvent
	next int
	full bool
}

func newRing() *auditRing { return &auditRing{buf: make([]auditEvent, ringSize)} }

// clip bounds what one event can cost: user names and file names come from the
// network.
func clip(s string) string {
	if len(s) > 200 {
		return strings.ToValidUTF8(s[:200], "") + "…"
	}
	return s
}

func (a *auditRing) add(e auditEvent) {
	e.User, e.Detail, e.Event, e.Result = clip(e.User), clip(e.Detail), clip(e.Event), clip(e.Result)
	a.mu.Lock()
	a.buf[a.next] = e
	a.next = (a.next + 1) % len(a.buf)
	if a.next == 0 {
		a.full = true
	}
	a.mu.Unlock()
}

// recent returns up to limit events, newest first, that match the filter. An
// empty filter field matches everything; user and event match exactly.
func (a *auditRing) recent(user, event, result string, limit int) []auditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := a.next
	if a.full {
		n = len(a.buf)
	}
	var out []auditEvent
	for i := 1; i <= n && len(out) < limit; i++ {
		e := a.buf[(a.next-i+len(a.buf))%len(a.buf)]
		if (user == "" || e.User == user) && (event == "" || e.Event == event) && (result == "" || e.Result == result) {
			out = append(out, e)
		}
	}
	return out
}

// detailText flattens the extra attributes of an event for display.
func detailText(attrs []any) string {
	var b strings.Builder
	for i := 0; i+1 < len(attrs); i += 2 {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%v=%v", attrs[i], attrs[i+1])
	}
	return b.String()
}

// newAudit returns the default audit sink: one logfmt line per event on
// stderr, which systemd sends to the journal. Find them with msg=audit.
// slog quotes and escapes every value, so a file name or a user name that
// contains a newline or a quote cannot forge a second line.
func newAudit() *slog.Logger { return NewAuditLogger("text") }

// NewAuditLogger is the audit sink for a format: "text" (key=value, the default)
// or "json" (one JSON object per line, for log platforms that would otherwise
// have to parse key=value). Both keep escaping every value.
func NewAuditLogger(format string) *slog.Logger { return auditLogger(os.Stderr, format) }

func auditLogger(w io.Writer, format string) *slog.Logger {
	if format == "json" {
		return slog.New(slog.NewJSONHandler(w, nil))
	}
	return slog.New(slog.NewTextHandler(w, nil))
}

// outcome is the result field for a worker answer: ok or its error code.
func outcome(code string) string {
	if code == "" {
		return "ok"
	}
	return code
}

// auditAs records who did what, from where, and how it ended. user is the
// canonical name once known, the typed name on a failed login. Never pass
// passwords, codes or tokens in attrs.
func (s *Server) auditAs(r *http.Request, user, auth, event, result string, attrs ...any) {
	args := append([]any{"event", event, "user", user, "ip", clientIP(r), "auth", auth, "result", result}, attrs...)
	s.Audit.Info("audit", args...)
	s.ring.add(auditEvent{Time: time.Now(), Event: event, User: user, IP: clientIP(r), Auth: auth, Result: result, Detail: detailText(attrs)})
}

// auditSess is auditAs for a signed-in session.
func (s *Server) auditSess(r *http.Request, sess *Session, event, result string, attrs ...any) {
	s.auditAs(r, sess.User, sess.Auth, event, result, attrs...)
}

// under is dir/name without a leading slash when dir is the share root. It
// is not path.Join on purpose: the log should show what was asked for, not a
// cleaned-up version that hides a "../".
func under(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}
