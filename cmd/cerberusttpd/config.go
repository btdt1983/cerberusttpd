// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
)

// readConfig parses "key = value" lines (full-line # comments, optional quotes).
// Keys are flag names, so the file and the command line stay in step.
func readConfig(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected key = value", path, n)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	return out, sc.Err()
}

// applyConfig sets every flag found in the file unless it was given on the
// command line, so the command line always wins.
func applyConfig(fs *flag.FlagSet, path string) error {
	cfg, err := readConfig(path)
	if err != nil {
		return err
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	for k, v := range cfg {
		if k == "config" || fs.Lookup(k) == nil {
			return fmt.Errorf("%s: unknown setting %q", path, k)
		}
		if given[k] {
			continue
		}
		if err := fs.Set(k, v); err != nil {
			return fmt.Errorf("%s: %s: %v", path, k, err)
		}
	}
	return nil
}
