// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
	"github.com/libdns/transip"
)

// DNS-01 credentials never travel on a command line (any local user can read
// /proc/<pid>/cmdline). `run` (root) reads the credentials file and hands the
// values to `serve` over an inherited pipe, fd 6, as a JSON object.

// readDNSCredentials reads the key = value credentials file for a provider.
// For transip, private-key-file names a file whose contents become the key.
func readDNSCredentials(provider, path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("dns-provider %s requires dns-credentials", provider)
	}
	cfg, err := readConfig(path)
	if err != nil {
		return nil, err
	}
	var allowed []string
	switch provider {
	case "cloudflare":
		allowed = []string{"api-token", "zone-token"}
	case "transip":
		allowed = []string{"login", "private-key-file"}
	default:
		return nil, fmt.Errorf("unknown dns-provider %q (cloudflare or transip)", provider)
	}
	out := map[string]string{}
	for k, v := range cfg {
		ok := false
		for _, a := range allowed {
			ok = ok || a == k
		}
		if !ok {
			return nil, fmt.Errorf("%s: unknown setting %q for %s", path, k, provider)
		}
		out[k] = v
	}
	if provider == "transip" {
		kf := out["private-key-file"]
		delete(out, "private-key-file")
		if kf == "" {
			return nil, fmt.Errorf("%s: private-key-file is required for transip", path)
		}
		if !filepath.IsAbs(kf) {
			kf = filepath.Join(filepath.Dir(path), kf)
		}
		pem, err := os.ReadFile(kf)
		if err != nil {
			return nil, err
		}
		out["private-key"] = string(pem)
	}
	for _, k := range required(provider) {
		if out[k] == "" {
			return nil, fmt.Errorf("%s: %s is required for %s", path, k, provider)
		}
	}
	return json.Marshal(out)
}

func required(provider string) []string {
	if provider == "transip" {
		return []string{"login", "private-key"}
	}
	return []string{"api-token"}
}

// newDNSProvider builds the libdns provider from the JSON that `run` sent.
func newDNSProvider(provider string, raw []byte) (certmagic.DNSProvider, error) {
	var c map[string]string
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	for _, k := range required(provider) {
		if c[k] == "" {
			return nil, fmt.Errorf("dns credentials: %s missing", k)
		}
	}
	switch provider {
	case "cloudflare":
		return &cloudflare.Provider{APIToken: c["api-token"], ZoneToken: c["zone-token"]}, nil
	case "transip":
		// "memory": keep API tokens off disk.
		return &transip.Provider{AuthLogin: c["login"], PrivateKey: c["private-key"], TokenStorage: "memory"}, nil
	}
	return nil, fmt.Errorf("unknown dns-provider %q", provider)
}
