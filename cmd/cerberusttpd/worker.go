// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"flag"
	"strconv"
	"time"

	"github.com/btdt1983/cerberusttpd/internal/worker"
)

func workerMain(args []string) error {
	fs := flag.NewFlagSet("worker", flag.ContinueOnError)
	scan := fs.String("scan", "", "virus scanner command for finished uploads")
	timeout := fs.Duration("scan-timeout", 5*time.Minute, "give up on a scan after this long")
	if err := fs.Parse(args); err != nil || fs.NArg() != 2 {
		return errors.New("usage: worker [-scan cmd] [-scan-timeout d] <root> <cache dir>")
	}
	sc, err := worker.ParseScan(*scan, *timeout)
	if err != nil {
		return err
	}
	return worker.Run(fs.Arg(0), fs.Arg(1), sc)
}

func cleanupMain(args []string) error {
	if len(args) != 3 {
		return errors.New("usage: cleanup <root> <seconds> <cache dir>")
	}
	secs, err := strconv.Atoi(args[1])
	if err != nil || secs <= 0 {
		return errors.New("bad max age")
	}
	return worker.Cleanup(args[0], args[2], time.Duration(secs)*time.Second)
}
