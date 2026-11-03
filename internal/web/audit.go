// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package web

import (
	"log/slog"
	"net/http"
	"os"
)

// newAudit returns the default audit sink: one logfmt line per event on
// stderr, which systemd sends to the journal. Find them with msg=audit.
// slog quotes and escapes every value, so a file name or a user name that
// contains a newline or a quote cannot forge a second line.
func newAudit() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
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
