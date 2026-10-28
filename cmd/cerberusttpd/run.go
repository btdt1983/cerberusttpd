// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/btdt1983/cerberusttpd/internal/helper"
	"github.com/btdt1983/cerberusttpd/internal/ipc"
	"github.com/btdt1983/cerberusttpd/internal/localca"
	"github.com/btdt1983/cerberusttpd/internal/mfa"
)

func init() {
	// Pdeathsig fires when the forking *thread* exits; keep main on one thread.
	runtime.LockOSThread()
}

func runMain(args []string) error {
	var o options
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	o.register(fs)
	fs.Parse(args)
	if o.config != "" {
		if err := applyConfig(fs, o.config); err != nil {
			return err
		}
	}
	if err := o.resolve(fs); err != nil {
		return err
	}

	if os.Geteuid() != 0 {
		return errors.New("must start as root (it drops privileges itself)")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	svc, err := user.Lookup(o.svcUser)
	if err != nil {
		return errors.New("service user " + o.svcUser + " does not exist: " + err.Error())
	}
	uid, _ := strconv.ParseUint(svc.Uid, 10, 32)
	gid, _ := strconv.ParseUint(svc.Gid, 10, 32)

	// The data dir and the CA key stay root-only; the network process gets
	// its own subdirectory.
	if err := os.MkdirAll(o.data, 0o700); err != nil {
		return err
	}
	if o.mode == "acme" {
		// serve keeps its ACME account and certificates in data/net and must be
		// able to walk through data. Everything else in there is 0700/0600.
		if err := os.Chmod(o.data, 0o711); err != nil {
			return err
		}
	}
	netDir := filepath.Join(o.data, "net")
	if err := os.MkdirAll(netDir, 0o700); err != nil {
		return err
	}
	if err := os.Chown(netDir, int(uid), int(gid)); err != nil {
		return err
	}

	cfg := helper.Config{Exe: exe, PAMService: o.pamService, MinUID: uint32(o.minUID), Root: o.root,
		DataDir: o.data, StaleAfter: o.staleAfter}
	switch o.twoFA {
	case "required":
		if cfg.MFA, err = mfa.Open(o.data); err != nil {
			return err
		}
	case "off":
		log.Printf("run: WARNING two-factor login is off")
	default:
		return errors.New("-2fa must be required or off")
	}
	if o.mode == "local" {
		var extra []string
		for _, n := range strings.Split(o.names, ",") {
			if n = strings.TrimSpace(n); n != "" {
				extra = append(extra, n)
			}
		}
		if cfg.CA, err = localca.Load(filepath.Join(o.data, "ca"), extra); err != nil {
			return err
		}
	}

	tcp, err := net.Listen("tcp", o.addr)
	if err != nil {
		return err
	}
	udp, err := net.ListenPacket("udp", o.addr)
	if err != nil {
		return err
	}
	tcpF, err := tcp.(*net.TCPListener).File()
	if err != nil {
		return err
	}
	udpF, err := udp.(*net.UDPConn).File()
	if err != nil {
		return err
	}
	mine, theirs, err := ipc.Pair()
	if err != nil {
		return err
	}

	var credsR *os.File
	if o.mode == "acme" && o.dnsProvider != "" {
		creds, err := readDNSCredentials(o.dnsProvider, o.dnsCreds)
		if err != nil {
			return err
		}
		r, wr, err := os.Pipe()
		if err != nil {
			return err
		}
		// A few hundred bytes fit the pipe buffer; no reader needed yet.
		if _, err := wr.Write(creds); err != nil {
			return err
		}
		wr.Close()
		credsR = r
	}

	cmd := exec.Command(exe, append([]string{"serve"}, o.args()...)...)
	cmd.Dir = "/"
	cmd.Env = []string{}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{tcpF, udpF, theirs} // fds 3, 4, 5
	if credsR != nil {
		cmd.ExtraFiles = append(cmd.ExtraFiles, credsR) // fd 6: DNS credentials
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{}},
		Pdeathsig:  syscall.SIGKILL,
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	tcpF.Close()
	udpF.Close()
	theirs.Close()
	if credsR != nil {
		credsR.Close()
	}
	log.Printf("run: network process pid=%d as %s; listening on %s (tcp+udp)", cmd.Process.Pid, o.svcUser, o.addr)

	// SIGTERM: ask the network process to drain and wait for it. Only an
	// unexpected death of that process is a failure (so Restart=on-failure fits).
	var stopping atomic.Bool
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		stopping.Store(true)
		cmd.Process.Signal(syscall.SIGTERM)
		time.AfterFunc(15*time.Second, func() { cmd.Process.Kill() })
	}()
	go func() {
		err := cmd.Wait()
		if err == nil || stopping.Load() {
			os.Exit(0)
		}
		log.Fatalf("run: network process exited unexpectedly: %v", err)
	}()
	if err := helper.Serve(mine, cfg); err != nil && !stopping.Load() {
		return err
	}
	select {} // the goroutine above decides the exit status
}
