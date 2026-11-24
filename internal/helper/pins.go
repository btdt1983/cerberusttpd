// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Automatic mapping trusts the user name the provider reports, and that name
// can change: when someone leaves and their user name is later given to a new
// person, the new person would otherwise inherit the first one's account and
// files. So the first automatic sign-in pins the account to the provider's
// object id, which is never reused, and a later sign-in with the same name but
// another object id is refused. An administrator settles it by hand in the
// users file (an entry there beats automatic mapping) and removes the pin.

type pinStore struct {
	mu   sync.Mutex
	file string
	m    map[string]string // unix user -> object id
}

func loadPins(dir string) *pinStore {
	p := &pinStore{file: filepath.Join(dir, "oidc-pins.json"), m: map[string]string{}}
	if b, err := os.ReadFile(p.file); err == nil {
		if json.Unmarshal(b, &p.m) != nil {
			log.Printf("helper: %s is unreadable: automatic mapping will refuse everybody until it is fixed", p.file)
			p.m = nil
		}
	}
	return p
}

// pinOID reports whether unixUser may sign in as this object id, pinning it
// the first time. It never allows an empty id.
func (s *server) pinOID(unixUser, oid string) bool {
	oid = strings.ToLower(oid)
	if oid == "" || s.pins == nil || s.pins.m == nil {
		return false
	}
	p := s.pins
	p.mu.Lock()
	defer p.mu.Unlock()
	if have, ok := p.m[unixUser]; ok {
		return have == oid
	}
	p.m[unixUser] = oid
	b, err := json.Marshal(p.m)
	if err == nil {
		err = writeAtomic(p.file, b)
	}
	if err != nil {
		delete(p.m, unixUser)
		log.Printf("helper: save %s: %v", p.file, err)
		return false
	}
	log.Printf("helper: pinned %q to object id %s", unixUser, oid)
	return true
}

// autoName turns a user name into the account name it maps to, or "" when the
// domain is not one of the allowed ones. The name is lower-cased: the account
// has to be created that way (sssd with case_sensitive = false does).
func autoName(upn string, domains []string) string {
	upn = strings.ToLower(strings.TrimSpace(upn))
	local, domain, ok := strings.Cut(upn, "@")
	if !ok || local == "" || strings.Contains(domain, "@") {
		return ""
	}
	for _, d := range domains {
		if strings.EqualFold(d, domain) {
			return upn
		}
	}
	return ""
}
