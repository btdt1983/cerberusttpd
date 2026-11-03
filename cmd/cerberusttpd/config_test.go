// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "c.conf")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func parse(t *testing.T, conf string, args ...string) (*options, error) {
	var o options
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	o.register(fs)
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	return &o, applyConfig(fs, conf)
}

func TestConfigApplies(t *testing.T) {
	o, err := parse(t, write(t, "# comment\n\naddr = \":9443\"\nroot='/srv/share'\n2fa = off\nmax-upload = 1000\nstale-after = 48h\n"))
	if err != nil {
		t.Fatal(err)
	}
	if o.addr != ":9443" || o.root != "/srv/share" || o.twoFA != "off" || o.maxUpload != 1000 || o.staleAfter != 48*time.Hour {
		t.Fatalf("got %+v", o)
	}
}

func TestCommandLineWins(t *testing.T) {
	o, err := parse(t, write(t, "addr = :9443\nroot = /a\n"), "-addr", ":1234")
	if err != nil {
		t.Fatal(err)
	}
	if o.addr != ":1234" || o.root != "/a" {
		t.Fatalf("got addr=%q root=%q", o.addr, o.root)
	}
}

func TestConfigErrors(t *testing.T) {
	for name, body := range map[string]string{
		"unknown key": "nope = 1\n",
		"no equals":   "addr :9443\n",
		"bad value":   "max-upload = lots\n",
		"nested cfg":  "config = /x\n",
	} {
		if _, err := parse(t, write(t, body)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestAlbumsSetting(t *testing.T) {
	check := func(conf string) error {
		var o options
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		o.register(fs)
		if conf != "" {
			if err := applyConfig(fs, write(t, conf)); err != nil {
				t.Fatal(err)
			}
		}
		return o.resolve(fs)
	}
	if err := check(""); err != nil {
		t.Errorf("default: %v", err)
	}
	if err := check("albums = off\n"); err != nil {
		t.Errorf("off: %v", err)
	}
	if err := check("albums = maybe\n"); err == nil {
		t.Error("albums = maybe accepted")
	}
	var o options
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	o.register(fs)
	fs.Parse([]string{"-albums", "off"})
	found := false
	for i, a := range o.args() {
		if a == "-albums" && o.args()[i+1] == "off" {
			found = true
		}
	}
	if !found {
		t.Error("albums is not passed on to the network process")
	}
}

const ssoOK = "oidc-issuer = https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0\n" +
	"oidc-client-id = abc\noidc-client-secret-file = /etc/cerberusttpd/oidc-secret\n" +
	"oidc-users = /etc/cerberusttpd/oidc-users\noidc-redirect-url = https://files.example.com:8443/oidc/callback\n"

func resolved(t *testing.T, conf string) (*options, error) {
	t.Helper()
	var o options
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	o.register(fs)
	if err := applyConfig(fs, write(t, conf)); err != nil {
		t.Fatal(err)
	}
	return &o, o.resolve(fs)
}

func TestSingleSignOnSettings(t *testing.T) {
	o, err := resolved(t, ssoOK)
	if err != nil || !o.oidcEnabled() || o.oidcLabel != "Microsoft" {
		t.Fatalf("valid settings: %v %+v", err, o)
	}
	if o, err := resolved(t, "2fa = off\n"); err != nil || o.oidcEnabled() {
		t.Errorf("off by default: %v", err)
	}
	bad := map[string]string{
		"missing secret": strings.Replace(ssoOK, "oidc-client-secret-file = /etc/cerberusttpd/oidc-secret\n", "", 1),
		"missing users":  strings.Replace(ssoOK, "oidc-users = /etc/cerberusttpd/oidc-users\n", "", 1),
		"only an issuer": "oidc-issuer = https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0\n",
		"http issuer":    strings.Replace(ssoOK, "https://login.microsoftonline.com", "http://login.microsoftonline.com", 1),
		"common tenant":  strings.Replace(ssoOK, "11111111-2222-3333-4444-555555555555", "common", 1),
		"organizations":  strings.Replace(ssoOK, "11111111-2222-3333-4444-555555555555", "organizations", 1),
		"consumers":      strings.Replace(ssoOK, "11111111-2222-3333-4444-555555555555", "Consumers", 1),
		"no tenant":      strings.Replace(ssoOK, "11111111-2222-3333-4444-555555555555/v2.0", "", 1),
		"http callback":  strings.Replace(ssoOK, "https://files", "http://files", 1),
		"wrong path":     strings.Replace(ssoOK, "/oidc/callback", "/callback", 1),
		"query in url":   strings.Replace(ssoOK, "/oidc/callback", "/oidc/callback?x=1", 1),
	}
	for name, conf := range bad {
		if _, err := resolved(t, conf); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Another provider with a plain issuer URL is fine.
	if _, err := resolved(t, strings.Replace(ssoOK, "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0", "https://sso.example.com/realms/corp", 1)); err != nil {
		t.Errorf("generic provider: %v", err)
	}
}

func TestSingleSignOnReachesTheNetworkProcessWithoutSecrets(t *testing.T) {
	o, err := resolved(t, ssoOK+"oidc-label = Contoso\n")
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(o.args(), " ")
	if !strings.Contains(args, "-oidc-label Contoso") || !strings.Contains(args, "-oidc-issuer https://") {
		t.Errorf("serve does not learn that sign-on is on: %s", args)
	}
	for _, leak := range []string{"secret", "oidc-users", "client-id", "redirect"} {
		if strings.Contains(args, leak) {
			t.Errorf("%q is passed to the network process: %s", leak, args)
		}
	}
}

func TestSingleSignOnFilesMustBeRootsAlone(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to check ownership")
	}
	dir := t.TempDir()
	secret, users := filepath.Join(dir, "secret"), filepath.Join(dir, "users")
	os.WriteFile(users, []byte("jan@example.com = jan\n"), 0o600)
	o := options{oidcIssuer: "https://sso.example.com", oidcClientID: "c", oidcSecretFile: secret, oidcUsers: users, oidcRedirect: "https://x/oidc/callback"}
	for name, c := range map[string]struct {
		mode os.FileMode
		body string
		ok   bool
	}{"good": {0o600, "s3cret\n", true}, "group readable": {0o640, "s3cret", false}, "world readable": {0o644, "s3cret", false}, "empty": {0o600, " \n", false}} {
		os.WriteFile(secret, []byte(c.body), c.mode)
		os.Chmod(secret, c.mode)
		cfg, err := o.loadOIDC()
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
		if err == nil && cfg.Secret != "s3cret" {
			t.Errorf("secret %q", cfg.Secret)
		}
	}
	os.WriteFile(secret, []byte("s3cret"), 0o600)
	os.Chmod(users, 0o666)
	if _, err := o.loadOIDC(); err == nil {
		t.Error("world-writable users file accepted")
	}
	if _, err := (&options{oidcSecretFile: filepath.Join(dir, "missing")}).loadOIDC(); err == nil {
		t.Error("missing secret file accepted")
	}
}
