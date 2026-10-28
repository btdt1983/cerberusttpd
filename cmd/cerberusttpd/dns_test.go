// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCloudflareCredentials(t *testing.T) {
	raw, err := readDNSCredentials("cloudflare", write(t, "api-token = abc\n"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := newDNSProvider("cloudflare", raw)
	if err != nil || p == nil {
		t.Fatalf("provider: %v", err)
	}
}

func TestTransIPCredentialsReadKeyFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "k.pem"), []byte("-----BEGIN PRIVATE KEY-----\nxx\n-----END PRIVATE KEY-----\n"), 0o600)
	conf := filepath.Join(dir, "dns.conf")
	os.WriteFile(conf, []byte("login = david\nprivate-key-file = k.pem\n"), 0o600)
	raw, err := readDNSCredentials("transip", conf)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	json.Unmarshal(raw, &m)
	if m["login"] != "david" || !strings.Contains(m["private-key"], "BEGIN PRIVATE KEY") || m["private-key-file"] != "" {
		t.Fatalf("got %v", m)
	}
	if _, err := newDNSProvider("transip", raw); err != nil {
		t.Fatal(err)
	}
}

func TestDNSCredentialErrors(t *testing.T) {
	for name, c := range map[string]struct{ provider, body string }{
		"unknown provider": {"route53", "api-token = x\n"},
		"unknown key":      {"cloudflare", "api-token = x\nnope = 1\n"},
		"missing token":    {"cloudflare", "zone-token = x\n"},
		"missing key file": {"transip", "login = d\n"},
	} {
		if _, err := readDNSCredentials(c.provider, write(t, c.body)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := readDNSCredentials("cloudflare", ""); err == nil {
		t.Error("empty path: expected an error")
	}
}

func TestACMEKeysInConfig(t *testing.T) {
	o, err := parse(t, write(t, "tls = acme\ndomain = files.example.com\ndns-provider = cloudflare\ndns-credentials = /etc/x\nacme-ca = staging\n"))
	if err != nil || o.dnsProvider != "cloudflare" || o.dnsCreds != "/etc/x" || o.acmeCA != "staging" {
		t.Fatalf("got %+v, %v", o, err)
	}
	args := strings.Join(o.args(), " ")
	if strings.Contains(args, "/etc/x") || !strings.Contains(args, "-dns-provider cloudflare") {
		t.Fatalf("args leak or miss: %s", args)
	}
}

func TestDomainImpliesACME(t *testing.T) {
	for name, c := range map[string]struct {
		body, mode, addr string
		bad              bool
	}{
		"domain only":           {"domain = files.example.com\n", "acme", ":443", false},
		"explicit addr":         {"domain = files.example.com\naddr = :8443\n", "acme", ":8443", false},
		"explicit acme":         {"tls = acme\ndomain = files.example.com\n", "acme", ":443", false},
		"no domain":             {"2fa = off\n", "local", ":8443", false},
		"domain with tls=local": {"tls = local\ndomain = files.example.com\n", "", "", true},
	} {
		var o options
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		o.register(fs)
		if err := applyConfig(fs, write(t, c.body)); err != nil {
			t.Fatal(err)
		}
		err := o.resolve(fs)
		if c.bad {
			if err == nil {
				t.Errorf("%s: expected an error", name)
			}
			continue
		}
		if err != nil || o.mode != c.mode || o.addr != c.addr {
			t.Errorf("%s: got mode=%q addr=%q err=%v", name, o.mode, o.addr, err)
		}
	}
}

func TestACMEHTTPKeepsAddrAndExcludesDNS(t *testing.T) {
	for name, c := range map[string]struct {
		body, addr string
		bad        bool
	}{
		"http challenge keeps 8443": {"domain = f.example.com\nacme-http-addr = 127.0.0.1:8080\n", ":8443", false},
		"with dns provider":         {"domain = f.example.com\nacme-http-addr = 127.0.0.1:8080\ndns-provider = cloudflare\n", "", true},
	} {
		var o options
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		o.register(fs)
		if err := applyConfig(fs, write(t, c.body)); err != nil {
			t.Fatal(err)
		}
		err := o.resolve(fs)
		if c.bad != (err != nil) || (!c.bad && (o.mode != "acme" || o.addr != c.addr)) {
			t.Errorf("%s: mode=%q addr=%q err=%v", name, o.mode, o.addr, err)
		}
	}
}
