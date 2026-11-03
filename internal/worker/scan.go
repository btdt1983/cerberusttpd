// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package worker

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// Scanner runs a virus scanner over a finished upload, as the uploading user,
// before the file gets its real name. The command comes from the root-owned
// settings: an absolute path plus fixed arguments, run without a shell, with
// the file's absolute path added as the last argument. It follows the exit
// codes of clamscan/clamdscan: 0 clean, 1 infected, anything else (or a
// timeout) is a failure, and a failed scan rejects the upload.
//
// This is a check at upload time. The owner can still change the file later,
// and files placed on the server by other means are not scanned.
type Scanner struct {
	Argv    []string
	Timeout time.Duration
}

// scanner is set once by Run; nil means no scanning.
var scanner *Scanner

var (
	errInfected = errors.New("infected")
	errScanFail = errors.New("scan failed")
)

const scanOutputMax = 4096

// capWriter keeps the first scanOutputMax bytes and drops the rest.
type capWriter struct{ buf bytes.Buffer }

func (w *capWriter) Write(p []byte) (int, error) {
	if room := scanOutputMax - w.buf.Len(); room > 0 {
		w.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// scan returns nil for a clean file, errInfected (with the scanner's name for
// the finding) or errScanFail.
func (s *Scanner) scan(file string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.Argv[0], append(append([]string{}, s.Argv[1:]...), file)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	cmd.Dir = "/"
	out := &capWriter{}
	cmd.Stdout, cmd.Stderr = out, out
	// A scanner may start helpers: stop the whole group when time runs out.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return "", nil
	case ctx.Err() != nil:
		return "", errScanFail
	case errors.As(err, &ee) && ee.ExitCode() == 1:
		return finding(out.buf.String(), file), errInfected
	}
	return "", errScanFail
}

// finding picks the name of what was found out of the scanner's output: for
// clamscan that is "<path>: Eicar-Test-Signature FOUND". Anything unexpected
// gives an empty name; the result is for the audit log and kept short.
func finding(output, file string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutSuffix(line, " FOUND")
		if !ok {
			continue
		}
		_, name, ok := strings.Cut(rest, ": ")
		if !ok {
			continue
		}
		name = strings.Map(func(r rune) rune {
			if r < 0x20 || r == 0x7f {
				return -1
			}
			return r
		}, name)
		return name[:min(len(name), 100)]
	}
	return ""
}

// scanPart scans the finished upload at part (a path below rootDir). It
// reports the response to send when the upload must be refused.
func scanPart(rootDir, part string) (refusal Response, ok bool) {
	if scanner == nil {
		return Response{}, true
	}
	name, err := scanner.scan(rootDir + "/" + part)
	switch err {
	case nil:
		return Response{}, true
	case errInfected:
		return Response{Err: "infected", Detail: name}, false
	}
	return Response{Err: "scanfail"}, false
}

// ParseScan turns the setting into a Scanner: an absolute path to an
// executable, then fixed arguments (split on spaces; no quoting, no shell).
func ParseScan(command string, timeout time.Duration) (*Scanner, error) {
	argv := strings.Fields(command)
	if len(argv) == 0 {
		return nil, nil
	}
	if !strings.HasPrefix(argv[0], "/") {
		return nil, errors.New("scan-command must start with the absolute path of the scanner")
	}
	fi, err := os.Stat(argv[0])
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return nil, errors.New(argv[0] + " is not an executable file")
	}
	if timeout <= 0 {
		return nil, errors.New("scan-timeout must be positive")
	}
	return &Scanner{Argv: argv, Timeout: timeout}, nil
}
