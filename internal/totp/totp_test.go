// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package totp

import (
	"encoding/base32"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA1 secret "12345678901234567890" (8 digits there; we use the last 6).
func TestRFC6238(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, tc := range []struct {
		unix int64
		want string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}} {
		got, err := code(secret, Counter(time.Unix(tc.unix, 0)))
		if err != nil || got != tc.want {
			t.Errorf("t=%d got %s want %s (%v)", tc.unix, got, tc.want, err)
		}
	}
}

func TestVerifyReplayAndSkew(t *testing.T) {
	s := NewSecret()
	now := time.Unix(1700000000, 0)
	c, _ := code(s, Counter(now))
	step, ok := Verify(s, c, now, 0)
	if !ok {
		t.Fatal("valid code rejected")
	}
	if _, ok := Verify(s, c, now, step); ok {
		t.Fatal("replay accepted")
	}
	prev, _ := code(s, Counter(now)-1)
	if _, ok := Verify(s, prev, now, 0); !ok {
		t.Fatal("previous step rejected")
	}
	old, _ := code(s, Counter(now)-2)
	if _, ok := Verify(s, old, now, 0); ok {
		t.Fatal("two steps old accepted")
	}
	if _, ok := Verify(s, "12345", now, 0); ok {
		t.Fatal("short code accepted")
	}
}
