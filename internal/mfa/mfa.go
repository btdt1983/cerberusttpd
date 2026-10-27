// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

// Package mfa stores each user's TOTP secret and recovery codes, encrypted at
// rest (AES-256-GCM, key kept next to the data, both root-only). Only the root
// helper uses it; the network process never sees a stored secret.
package mfa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cerberusttpd/internal/totp"
)

const recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

type record struct {
	Secret   string   `json:"secret"`
	Last     uint64   `json:"last"`     // newest TOTP step already used
	Recovery []string `json:"recovery"` // hex sha256 of unused codes
}

type file struct {
	Nonce []byte `json:"nonce"`
	CT    []byte `json:"ct"`
}

type Store struct {
	dir  string
	aead cipher.AEAD
	mu   sync.Mutex
}

// Open prepares dir (0700) and loads or creates the encryption key.
func Open(dataDir string) (*Store, error) {
	dir := filepath.Join(dataDir, "2fa")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dataDir, "2fa.key")
	key, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		err = os.WriteFile(keyPath, key, 0o600)
	}
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("mfa: bad key file")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &Store{dir: dir, aead: g}, nil
}

func (s *Store) path(user string) string { return filepath.Join(s.dir, user+".json") }

func (s *Store) Enrolled(user string) bool {
	_, err := os.Stat(s.path(user))
	return err == nil
}

func (s *Store) load(user string) (*record, error) {
	b, err := os.ReadFile(s.path(user))
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	pt, err := s.aead.Open(nil, f.Nonce, f.CT, []byte(user))
	if err != nil {
		return nil, err
	}
	var r record
	return &r, json.Unmarshal(pt, &r)
}

func (s *Store) save(user string, r *record) error {
	pt, err := json.Marshal(r)
	if err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	b, err := json.Marshal(file{Nonce: nonce, CT: s.aead.Seal(nil, nonce, pt, []byte(user))})
	if err != nil {
		return err
	}
	tmp := s.path(user) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path(user))
}

// Enroll stores secret for user after the caller verified a first code at step,
// and returns ten-ish fresh recovery codes in display form (shown only once).
func (s *Store) Enroll(user, secret string, step uint64) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var shown, hashed []string
	for i := 0; i < 8; i++ {
		c := randomCode()
		shown = append(shown, c[:5]+"-"+c[5:])
		hashed = append(hashed, hash(c))
	}
	return shown, s.save(user, &record{Secret: secret, Last: step, Recovery: hashed})
}

// Check accepts a TOTP code or an unused recovery code, and marks it used.
func (s *Store) Check(user, input string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.load(user)
	if err != nil {
		return false
	}
	in := strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(input))
	if step, ok := totp.Verify(r.Secret, in, now, r.Last); ok {
		r.Last = step
		return s.save(user, r) == nil
	}
	h := hash(in)
	hit := -1
	for i, want := range r.Recovery { // compare all: no early exit
		if subtle.ConstantTimeCompare([]byte(want), []byte(h)) == 1 {
			hit = i
		}
	}
	if hit < 0 {
		return false
	}
	r.Recovery = append(r.Recovery[:hit], r.Recovery[hit+1:]...)
	return s.save(user, r) == nil
}

// Reset removes a user's 2FA so they enrol again at next login.
func (s *Store) Reset(user string) error { return os.Remove(s.path(user)) }

func hash(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

func randomCode() string {
	b := make([]byte, 10)
	rand.Read(b)
	out := make([]byte, 10)
	for i, x := range b {
		out[i] = recoveryAlphabet[int(x)%len(recoveryAlphabet)]
	}
	return string(out)
}
