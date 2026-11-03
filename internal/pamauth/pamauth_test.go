// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package pamauth

import (
	"testing"

	"github.com/msteinert/pam/v2"
)

func TestConverse(t *testing.T) {
	pw := "secret"
	c := converse(&pw)
	// plain messages (pam_sss: expiry warnings, "cached credentials") need no answer
	for _, s := range []pam.Style{pam.TextInfo, pam.ErrorMsg} {
		if got, err := c(s, "Authenticated with cached credentials"); err != nil || got != "" {
			t.Errorf("style %v: %q, %v", s, got, err)
		}
	}
	if got, err := c(pam.PromptEchoOff, "Password: "); err != nil || got != "secret" {
		t.Errorf("first prompt: %q, %v", got, err)
	}
	// a second hidden prompt (forced change, new password) and any visible one cannot be answered
	if _, err := c(pam.PromptEchoOff, "New password: "); err == nil {
		t.Error("second hidden prompt answered")
	}
	if _, err := c(pam.PromptEchoOn, "Verification code: "); err == nil {
		t.Error("visible prompt answered")
	}
	// account management only: nothing may be asked
	n := converse(nil)
	if _, err := n(pam.PromptEchoOff, "Password: "); err == nil {
		t.Error("prompt answered without a password")
	}
	if _, err := n(pam.TextInfo, "note"); err != nil {
		t.Error(err)
	}
}
