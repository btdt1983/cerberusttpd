// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"os"
	"os/user"
	"path/filepath"
	"syscall"
	"testing"
)

func TestShareFileNameHiddenBehindPassword(t *testing.T) {
	s := testServer(t)
	g := s.newGrant("jan", false)
	plain := s.shareCreate(Request{Grant: g, Path: "docs/open.txt", TTL: 60})
	locked := s.shareCreate(Request{Grant: g, Path: "docs/secret.txt", TTL: 60, Password: "x"})
	if in := s.shareInfo(Request{Token: plain.Token}); in.Name != "open.txt" {
		t.Errorf("link without a password: %+v", in)
	}
	if in := s.shareInfo(Request{Token: locked.Token}); !in.OK || in.Name != "" || !in.HasPW {
		t.Errorf("the file name is visible before the password: %+v", in)
	}
}

func TestShareRequirePassword(t *testing.T) {
	s := testServer(t)
	g := s.newGrant("jan", false)
	old := s.shareCreate(Request{Grant: g, Path: "a.txt", TTL: 60}) // made before the policy
	s.ShareRequirePW = true
	if r := s.shareCreate(Request{Grant: g, Path: "a.txt", TTL: 60}); r.Err != "needpw" {
		t.Errorf("create without a password: %q", r.Err)
	}
	if r := s.shareCreate(Request{Grant: g, Path: "a.txt", TTL: 60, Password: "pw"}); r.Err != "" {
		t.Errorf("create with a password: %q", r.Err)
	}
	// A link without a password that exists from before stops working.
	if in := s.shareInfo(Request{Token: old.Token}); in.Err != "unavailable" || in.Detail != "nopassword" {
		t.Errorf("old link still answers: %+v", in)
	}
	if r, f := s.shareOpen(Request{Token: old.Token}); r.Err != "unavailable" || r.Detail != "nopassword" || f != nil {
		t.Errorf("old link still opens: %+v", r)
	}
}

func TestPasswordLoginOff(t *testing.T) {
	s := testServer(t)
	s.PasswordLogin = false
	if r, f := s.login(Request{User: "nobody", Password: "x"}); r.Err != "disabled" || f != nil {
		t.Errorf("a password login was tried while it is off: %+v", r)
	}
}

func TestLoginGroup(t *testing.T) {
	s := testServer(t)
	s.MinUID = 1
	if _, ok := s.eligibleName("nobody"); !ok {
		t.Fatal("nobody should be eligible without a login group")
	}
	s.LoginGroup = "root" // nobody is not in it
	if _, ok := s.eligibleName("nobody"); ok {
		t.Error("a non-member may sign in")
	}
	s.LoginGroup = "no-such-group-xyz" // fail closed
	if _, ok := s.eligibleName("nobody"); ok {
		t.Error("a missing login group lets everybody in")
	}
	// The recipient of a share and the owner of a link go through the same gate.
	s.LoginGroup = ""
	if _, ok := s.eligibleName("nobody"); !ok {
		t.Error("lifting the restriction does not restore access")
	}
}

func TestAdminGroup(t *testing.T) {
	root, err := user.Lookup("root")
	if err != nil {
		t.Skip(err)
	}
	if _, admin, err := credFor(root, "root"); err != nil || !admin {
		t.Errorf("member of the admin group is not an admin: %v %v", admin, err)
	}
	if _, admin, _ := credFor(root, "no-such-group-xyz"); admin {
		t.Error("a missing group makes somebody admin")
	}
	if _, admin, _ := credFor(root, ""); admin {
		t.Error("an empty admin group makes somebody admin")
	}
}

func TestAutoName(t *testing.T) {
	d := []string{"uwv.nl", "Test.Example"}
	for in, want := range map[string]string{
		"Jan.Jansen@UWV.nl":  "jan.jansen@uwv.nl",
		" jan@uwv.nl ":       "jan@uwv.nl",
		"jan@test.example":   "jan@test.example",
		"jan@evil.nl":        "",
		"jan@sub.uwv.nl":     "",
		"jan@uwv.nl.evil.nl": "",
		"@uwv.nl":            "",
		"jan":                "",
		"":                   "",
		"a@b@uwv.nl":         "",
		"jan@uwv.nl@evil.nl": "",
	} {
		if got := autoName(in, d); got != want {
			t.Errorf("autoName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPins(t *testing.T) {
	s := testServer(t)
	s.pins = loadPins(s.DataDir)
	if !s.pinOID("jan@uwv.nl", "AAA-1") {
		t.Fatal("first sign-in is refused")
	}
	if !s.pinOID("jan@uwv.nl", "aaa-1") {
		t.Error("the same person (case differs) is refused")
	}
	if s.pinOID("jan@uwv.nl", "bbb-2") {
		t.Error("another person with the same name is accepted")
	}
	if s.pinOID("piet@uwv.nl", "") {
		t.Error("an empty object id is accepted")
	}
	// The pin survives a restart and is not world readable.
	s.pins = loadPins(s.DataDir)
	if s.pinOID("jan@uwv.nl", "bbb-2") || !s.pinOID("jan@uwv.nl", "aaa-1") {
		t.Error("the pin was lost")
	}
	if fi, err := os.Stat(filepath.Join(s.DataDir, "oidc-pins.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("pins file: %v %v", fi, err)
	}
	// A broken pins file refuses everybody rather than pinning over it.
	os.WriteFile(filepath.Join(s.DataDir, "oidc-pins.json"), []byte("{broken"), 0o600)
	s.pins = loadPins(s.DataDir)
	if s.pinOID("kees@uwv.nl", "ccc-3") {
		t.Error("a broken pins file lets somebody in")
	}
}

func TestHomePlanRefusals(t *testing.T) {
	s := testServer(t)
	u := &user.User{Username: "jan", HomeDir: "/home/jan"}
	if _, err := s.homePlan(u); err == nil {
		t.Error("create-home off still plans")
	}
	s.CreateHome, s.CreateHomeBase = true, "/home"
	s.Root = "/srv/share"
	if _, err := s.homePlan(u); err == nil {
		t.Error("a shared root still plans")
	}
	s.Root = ""
	for _, home := range []string{"/", "/etc", "/home", "/home/", "/home/../etc/x", "/homey/jan", "relative/jan", "/home/a/b/c/d", "/home//jan", "/var/lib/x"} {
		if _, err := s.homePlan(&user.User{Username: "jan", HomeDir: home}); err == nil {
			t.Errorf("home %q is planned", home)
		}
	}
	// An existing home needs no plan: homeReady is true without create-home.
	s.CreateHome = false
	if !s.homeReady(&user.User{Username: "root", HomeDir: os.TempDir()}) {
		t.Error("an existing folder is not ready")
	}
}

func TestHomePlanBelowBase(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to own the base directory")
	}
	base := t.TempDir()
	os.Chmod(base, 0o755)
	s := testServer(t)
	s.CreateHome, s.CreateHomeBase = true, base
	missing, err := s.homePlan(&user.User{Username: "jan", HomeDir: base + "/uwv.nl/jan"})
	if err != nil || len(missing) != 1 || missing[0] != base+"/uwv.nl" {
		t.Fatalf("plan: %v %v", missing, err)
	}
	if m, err := s.homePlan(&user.User{Username: "jan", HomeDir: base + "/jan"}); err != nil || len(m) != 0 {
		t.Errorf("plan for a direct child: %v %v", m, err)
	}
	// A base that others can write in is refused.
	os.Chmod(base, 0o777)
	if _, err := s.homePlan(&user.User{Username: "jan", HomeDir: base + "/jan"}); err == nil {
		t.Error("a world-writable base is accepted")
	}
	os.Chmod(base, 0o755)
	// A link in the way is refused.
	os.Symlink("/etc", base+"/link")
	if _, err := s.homePlan(&user.User{Username: "jan", HomeDir: base + "/link/jan"}); err == nil {
		t.Error("a symlinked parent is accepted")
	}
}

func TestMapIdentity(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("the users file must be owned by root")
	}
	users := writeUsers(t, 0o600, "jan.jansen@uwv.nl = jjansen\noid:aaa = piet@uwv.nl\nbad@uwv.nl = -\n")
	s := testServer(t)
	s.OIDC = &OIDC{UsersFile: users}
	for name, c := range map[string]struct {
		id       Identity
		domains  []string
		want     string
		wantAuto bool
	}{
		"explicit entry":                  {Identity{UPN: "jan.jansen@uwv.nl"}, []string{"uwv.nl"}, "jjansen", false},
		"explicit entry without auto-map": {Identity{UPN: "jan.jansen@uwv.nl"}, nil, "jjansen", false},
		"object id entry beats the name":  {Identity{OID: "aaa", UPN: "kees@uwv.nl"}, []string{"uwv.nl"}, "piet@uwv.nl", false},
		"deny entry beats auto-map":       {Identity{UPN: "bad@uwv.nl"}, []string{"uwv.nl"}, "-", false},
		"unknown person, allowed domain":  {Identity{UPN: "Kees@UWV.nl"}, []string{"uwv.nl"}, "kees@uwv.nl", true},
		"unknown person, other domain":    {Identity{UPN: "kees@evil.nl"}, []string{"uwv.nl"}, "", false},
		"unknown person, auto-map off":    {Identity{UPN: "kees@uwv.nl"}, nil, "", false},
		"no user name at all":             {Identity{OID: "zzz"}, []string{"uwv.nl"}, "", false},
	} {
		s.OIDC.AutoDomains = c.domains
		got, auto, err := s.mapIdentity(c.id)
		if err != nil || got != c.want || auto != c.wantAuto {
			t.Errorf("%s: %q auto=%v err=%v, want %q auto=%v", name, got, auto, err, c.want, c.wantAuto)
		}
	}
	// "-" is never a usable account name.
	if _, ok := s.eligibleName("-"); ok {
		t.Error("the deny marker is an account")
	}
}

func TestCopySkel(t *testing.T) {
	skel := t.TempDir()
	os.WriteFile(filepath.Join(skel, ".bashrc"), []byte("alias x=y\n"), 0o644)
	os.WriteFile(filepath.Join(skel, "run.sh"), []byte("#!/bin/sh\n"), 0o755)
	os.MkdirAll(filepath.Join(skel, ".config", "sub"), 0o755)
	os.WriteFile(filepath.Join(skel, ".config", "sub", "f"), []byte("x"), 0o666)
	os.Symlink("/etc/shadow", filepath.Join(skel, "link"))
	home := t.TempDir()
	if err := copySkel(skel, home); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]os.FileMode{".bashrc": 0o600, "run.sh": 0o700, ".config": 0o700, ".config/sub": 0o700, ".config/sub/f": 0o600} {
		fi, err := os.Lstat(filepath.Join(home, name))
		if err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s: %v %v, want %v", name, fi, err, want)
		}
	}
	if _, err := os.Lstat(filepath.Join(home, "link")); err == nil {
		t.Error("a link was copied")
	}
	if b, _ := os.ReadFile(filepath.Join(home, ".bashrc")); string(b) != "alias x=y\n" {
		t.Errorf("content: %q", b)
	}
	// No skeleton is fine; too many entries is not.
	if err := copySkel(filepath.Join(skel, "nope"), t.TempDir()); err != nil {
		t.Errorf("missing skeleton: %v", err)
	}
	big := t.TempDir()
	for i := 0; i <= skelMaxEntries; i++ {
		os.WriteFile(filepath.Join(big, "f"+itoa3(i)), nil, 0o644)
	}
	if err := copySkel(big, t.TempDir()); err == nil {
		t.Error("an enormous skeleton is copied")
	}
}

func itoa3(i int) string {
	return string(rune('a'+i/26/26%26)) + string(rune('a'+i/26%26)) + string(rune('a'+i%26))
}

func TestFillHomeGivesTheFilesToTheUser(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to change owners")
	}
	skel := t.TempDir()
	os.WriteFile(filepath.Join(skel, ".bashrc"), []byte("x"), 0o644)
	home := filepath.Join(t.TempDir(), "jan")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := fillHome(home, skel, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{home, filepath.Join(home, ".bashrc")} {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st := fi.Sys().(*syscall.Stat_t); st.Uid != 65534 || st.Gid != 65534 {
			t.Errorf("%s belongs to %d:%d", p, st.Uid, st.Gid)
		}
	}
	if fi, _ := os.Stat(home); fi.Mode().Perm() != 0o700 {
		t.Errorf("home mode %v", fi.Mode().Perm())
	}
}
