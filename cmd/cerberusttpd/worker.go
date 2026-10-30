// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"strconv"
	"time"

	"github.com/btdt1983/cerberusttpd/internal/worker"
)

func workerMain(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: worker <root> <cache dir>")
	}
	return worker.Run(args[0], args[1])
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
