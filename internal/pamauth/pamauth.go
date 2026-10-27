// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

// Package pamauth checks a username/password against the system PAM stack.
package pamauth

import (
	"errors"
	"sync"

	"github.com/msteinert/pam/v2"
)

// PAM modules are not all thread-safe; serialise transactions.
var mu sync.Mutex

var ErrDenied = errors.New("authentication failed")

// Check runs authenticate and account management (expired/locked accounts) for
// service. No PAM session is opened.
func Check(service, user, password, rhost string) error {
	mu.Lock()
	defer mu.Unlock()
	t, err := pam.StartFunc(service, user, func(s pam.Style, msg string) (string, error) {
		if s == pam.PromptEchoOff {
			return password, nil
		}
		return "", errors.New("unsupported PAM prompt")
	})
	if err != nil {
		return err
	}
	defer t.End()
	if rhost != "" {
		_ = t.SetItem(pam.Rhost, rhost)
	}
	_ = t.SetItem(pam.Tty, "cerberusttpd")
	if err := t.Authenticate(0); err != nil {
		return ErrDenied
	}
	if err := t.AcctMgmt(0); err != nil {
		return ErrDenied
	}
	return nil
}
