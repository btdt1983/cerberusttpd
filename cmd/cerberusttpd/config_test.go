// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"os"
	"path/filepath"
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
