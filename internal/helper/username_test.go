// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidUser(t *testing.T) {
	good := []string{"jan", "jan.jansen", "Jan.Jansen", "Jan.Jansen@Corp.local", "jan.jansen@corp.example.com", "_svc", "a-b_c", "j", "1abc", strings.Repeat("a", 128)}
	bad := []string{"", "../x", "..", ".", ".hidden", "-opt", "PC01$", "12345", "0", "CORP\\jan", "a/b", "jan jansen", "jan\n", "jan\x00", "é", "a:b", "a,b", "@corp", strings.Repeat("a", 129)}
	for _, n := range good {
		if !ValidUser(n) {
			t.Errorf("%q refused", n)
		}
	}
	for _, n := range bad {
		if ValidUser(n) {
			t.Errorf("%q accepted", n)
		}
	}
}

func TestLimiterKeyIgnoresCase(t *testing.T) {
	if limiterKey("Jan.Jansen@Corp.local") != limiterKey("jan.jansen@corp.local") {
		t.Error("case variants get separate budgets")
	}
}

func TestHomeOK(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	os.WriteFile(file, nil, 0o600)
	u := &user.User{Username: "x", HomeDir: filepath.Join(dir, "no-such-home")}
	for name, c := range map[string]struct {
		root string
		want bool
	}{"shared root exists": {dir, true}, "shared root missing": {filepath.Join(dir, "gone"), false}, "root is a file": {file, false},
		"own home missing": {"", false}} {
		if got := (&server{Config: Config{Root: c.root}}).homeOK(u); got != c.want {
			t.Errorf("%s: %v", name, got)
		}
	}
	u.HomeDir = dir
	if !(&server{}).homeOK(u) {
		t.Error("existing home refused")
	}
}
