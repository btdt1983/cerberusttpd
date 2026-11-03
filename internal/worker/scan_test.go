// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package worker

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// stub writes a fake scanner. It follows clamscan: exit 0 clean, 1 infected.
func stub(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "scanner.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

const eicarStub = `f="$1"
if grep -q EICAR "$f"; then echo "$f: Eicar-Test-Signature FOUND"; exit 1; fi
exit 0`

// scanUpload installs a scanner for one test and starts an upload of data.
func scanUpload(t *testing.T, dir string, sc *Scanner, data string) Response {
	t.Helper()
	old, oldRoot := scanner, scanRoot
	scanner, scanRoot = sc, dir
	t.Cleanup(func() { scanner, scanRoot = old, oldRoot })
	root := openRoot(t, dir)
	id := strings.Repeat("a", 32)
	if err := os.WriteFile(filepath.Join(dir, partPrefix+id+".part"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, partPrefix+id+".json"), []byte(`{"name":"f.txt","length":`+itoa(len(data))+`}`), 0o600)
	return finish(root, "", id, meta{Name: "f.txt", Length: int64(len(data))})
}

func itoa(n int) string { return strconv.Itoa(n) }

func left(t *testing.T, dir string) []string {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func TestScanCleanFileIsPublished(t *testing.T) {
	dir := t.TempDir()
	sc := &Scanner{Argv: []string{stub(t, t.TempDir(), eicarStub)}, Timeout: 10 * time.Second}
	if r := scanUpload(t, dir, sc, "hello world"); r.Err != "" || r.Name != "f.txt" {
		t.Fatalf("%+v", r)
	}
	if got := left(t, dir); len(got) != 1 || got[0] != "f.txt" {
		t.Errorf("directory holds %v", got)
	}
}

func TestScanInfectedFileIsRefusedAndRemoved(t *testing.T) {
	dir := t.TempDir()
	sc := &Scanner{Argv: []string{stub(t, t.TempDir(), eicarStub)}, Timeout: 10 * time.Second}
	r := scanUpload(t, dir, sc, "X5O EICAR test")
	if r.Err != "infected" || r.Detail != "Eicar-Test-Signature" || r.Name != "f.txt" {
		t.Fatalf("%+v", r)
	}
	if got := left(t, dir); len(got) != 0 {
		t.Errorf("an infected upload left %v behind", got)
	}
}

func TestScanFailureRefusesTheUpload(t *testing.T) {
	for name, body := range map[string]string{
		"scanner error":   "echo broken >&2; exit 2",
		"killed":          "kill -9 $$",
		"hangs":           "sleep 30",
		"hangs with kids": "sleep 30 & wait",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			start := time.Now()
			sc := &Scanner{Argv: []string{stub(t, t.TempDir(), body)}, Timeout: 700 * time.Millisecond}
			r := scanUpload(t, dir, sc, "hello")
			if r.Err != "scanfail" {
				t.Fatalf("%+v", r)
			}
			if time.Since(start) > 10*time.Second {
				t.Errorf("took %v", time.Since(start))
			}
			if got := left(t, dir); len(got) != 0 {
				t.Errorf("left %v behind", got)
			}
		})
	}
	// A scanner that is gone is a failure too, not a pass.
	dir := t.TempDir()
	if r := scanUpload(t, dir, &Scanner{Argv: []string{"/nonexistent/scanner"}, Timeout: time.Second}, "x"); r.Err != "scanfail" {
		t.Errorf("%+v", r)
	}
}

func TestScannerGetsOnlyTheFileAndAFixedEnvironment(t *testing.T) {
	dir, out := t.TempDir(), filepath.Join(t.TempDir(), "seen")
	s := stub(t, t.TempDir(), `echo "$#|$*|$(env | sort | tr '\n' ,)" > `+out+`; exit 0`)
	sc := &Scanner{Argv: []string{s, "--fdpass", "--no-summary"}, Timeout: 10 * time.Second}
	t.Setenv("SECRET_TOKEN", "leak")
	if r := scanUpload(t, dir, sc, "hello"); r.Err != "" {
		t.Fatal(r)
	}
	b, _ := os.ReadFile(out)
	seen := string(b)
	if !strings.HasPrefix(seen, "3|--fdpass --no-summary "+dir+"/"+partPrefix) || strings.Contains(seen, "SECRET_TOKEN") || !strings.Contains(seen, "PATH=/usr/bin:/bin") {
		t.Errorf("scanner saw: %s", seen)
	}
}

func TestScanSkippedForEmptyFilesAndWhenOff(t *testing.T) {
	dir := t.TempDir()
	bad := &Scanner{Argv: []string{stub(t, t.TempDir(), "exit 2")}, Timeout: time.Second}
	if r := scanUpload(t, dir, nil, "hello"); r.Err != "" {
		t.Errorf("no scanner: %+v", r)
	}
	// nothing to scan in an empty file; finish is called with Length 0 for those
	scanner, scanRoot = bad, dir
	defer func() { scanner, scanRoot = nil, "" }()
	root := openRoot(t, dir)
	id := strings.Repeat("b", 32)
	os.WriteFile(filepath.Join(dir, partPrefix+id+".part"), nil, 0o600)
	if r := finish(root, "", id, meta{Name: "empty.txt"}); r.Err != "" {
		t.Errorf("empty file: %+v", r)
	}
}

func TestFindingIsShortAndPlain(t *testing.T) {
	for in, want := range map[string]string{
		"/tmp/x: Eicar-Test-Signature FOUND\n\n----------- SCAN SUMMARY\n": "Eicar-Test-Signature",
		"/tmp/x: Win.Test.EICAR_HDB-1 FOUND":                               "Win.Test.EICAR_HDB-1",
		"/tmp/a: b: Odd Name FOUND":                                        "b: Odd Name",
		"nothing here":                                                     "",
		"/tmp/x: bad\x1b[31mname\n FOUND":                                  "",
		"/tmp/x: " + strings.Repeat("n", 300) + " FOUND":                   strings.Repeat("n", 100),
	} {
		if got := finding(in, "/tmp/x"); got != want {
			t.Errorf("%q -> %q want %q", in, got, want)
		}
	}
}

func TestParseScan(t *testing.T) {
	good := stub(t, t.TempDir(), "exit 0")
	if sc, err := ParseScan(good+" --a --b", time.Minute); err != nil || len(sc.Argv) != 3 {
		t.Errorf("%v %+v", err, sc)
	}
	if sc, err := ParseScan("", time.Minute); sc != nil || err != nil {
		t.Errorf("empty setting: %v %v", sc, err)
	}
	for name, cmd := range map[string]string{"relative": "clamdscan --fdpass", "missing": "/nonexistent/x", "directory": "/tmp", "not executable": "/etc/passwd"} {
		if _, err := ParseScan(cmd, time.Minute); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseScan(good, 0); err == nil {
		t.Error("zero timeout accepted")
	}
}
