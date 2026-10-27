// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

// Package totp implements RFC 6238 (HMAC-SHA1, 6 digits, 30 s), the profile
// every authenticator app supports.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

const (
	Period = 30
	Digits = 6
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns 160 random bits as unpadded base32.
func NewSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b32.EncodeToString(b)
}

func code(secret string, counter uint64) (string, error) {
	key, err := b32.DecodeString(secret)
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	o := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[o:o+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", Digits, v%1000000), nil
}

// Counter is the time step containing t.
func Counter(t time.Time) uint64 { return uint64(t.Unix() / Period) }

// Verify accepts the code for the previous, current or next step, but only a
// step newer than last, so a code cannot be used twice. It returns the step used.
func Verify(secret, input string, now time.Time, last uint64) (uint64, bool) {
	if len(input) != Digits {
		return 0, false
	}
	cur := Counter(now)
	var hit uint64
	ok := false
	for c := cur - 1; c <= cur+1; c++ { // no early exit: constant work
		want, err := code(secret, c)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(input)) == 1 && c > last {
			hit, ok = c, true
		}
	}
	return hit, ok
}

// URI is the otpauth:// provisioning string shown as a QR code.
func URI(issuer, account, secret string) string {
	v := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + url.PathEscape(issuer) + ":" + url.PathEscape(account) + "?" + v.Encode()
}
