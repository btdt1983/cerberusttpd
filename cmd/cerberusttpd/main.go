// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

// cerberusttpd runs as three kinds of process:
//
//	run     (root)       binds the ports, holds the CA key, does PAM, spawns the rest
//	serve   (service user) HTTP/1.1, HTTP/2 and HTTP/3; talks to run over a socketpair
//	worker  (logged-in user) per-session file access
//	cleanup (a user)     removes that user's abandoned uploads; started by run
//	2fa-reset <user>     (root) forget a user's 2FA so they enrol again
//	version              print the version
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"
)

func main() {
	cmd := "run"
	args := os.Args[1:]
	if len(args) > 0 && (args[0] == "run" || args[0] == "serve" || args[0] == "worker" || args[0] == "cleanup" || args[0] == "2fa-reset" || args[0] == "version") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "run":
		err = runMain(args)
	case "serve":
		err = serveMain(args)
	case "worker":
		err = workerMain(args)
	case "cleanup":
		err = cleanupMain(args)
	case "2fa-reset":
		err = resetMain(args)
	case "version":
		fmt.Println("cerberusttpd", version)
	}
	if err != nil {
		log.Fatalf("%s: %v", cmd, err)
	}
}

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

type options struct {
	addr, root, data, mode, names, domains, email, svcUser, pamService, twoFA, config string

	minUID     uint
	maxUpload  int64
	staleAfter time.Duration
}

func (o *options) register(fs *flag.FlagSet) {
	fs.StringVar(&o.config, "config", "", "settings file with key = value lines (command line wins)")
	fs.StringVar(&o.addr, "addr", ":8443", "listen address (TCP for HTTP/1.1+2, UDP for HTTP/3)")
	fs.StringVar(&o.root, "root", "", "directory shared with every user (default: each user's home)")
	fs.StringVar(&o.data, "data", "/var/lib/cerberusttpd", "state directory (CA key, certificates)")
	fs.StringVar(&o.mode, "tls", "local", "certificate mode: local (private CA) or acme (public domain)")
	fs.StringVar(&o.names, "names", "", "extra DNS names/IPs for the local certificate, comma separated")
	fs.StringVar(&o.domains, "domain", "", "acme: domain(s), comma separated")
	fs.StringVar(&o.email, "acme-email", "", "acme: contact email")
	fs.StringVar(&o.svcUser, "user", "cerberusttpd", "unprivileged user for the network process")
	fs.StringVar(&o.pamService, "pam-service", "cerberusttpd", "PAM service name (/etc/pam.d/<name>)")
	fs.StringVar(&o.twoFA, "2fa", "required", "two-factor login: required (everyone enrols a TOTP app) or off")
	fs.Int64Var(&o.maxUpload, "max-upload", 20<<30, "largest allowed upload in bytes (0 = unlimited)")
	fs.DurationVar(&o.staleAfter, "stale-after", 7*24*time.Hour, "remove abandoned uploads untouched for this long (0 = never)")
	fs.UintVar(&o.minUID, "min-uid", 1000, "lowest uid allowed to log in")
}

func (o *options) args() []string {
	return []string{
		"-addr", o.addr, "-root", o.root, "-data", o.data, "-tls", o.mode,
		"-names", o.names, "-domain", o.domains, "-acme-email", o.email,
		"-user", o.svcUser, "-pam-service", o.pamService, "-min-uid", fmt.Sprint(o.minUID),
		"-2fa", o.twoFA, "-max-upload", fmt.Sprint(o.maxUpload), "-stale-after", o.staleAfter.String(),
	}
}
