// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
)

import "github.com/btdt1983/cerberusttpd/internal/mfa"

func resetMain(args []string) error {
	fs := flag.NewFlagSet("2fa-reset", flag.ExitOnError)
	data := fs.String("data", "/var/lib/cerberusttpd", "state directory")
	conf := fs.String("config", "", "settings file; its data = ... is used unless -data is given")
	fs.Parse(args)
	if *conf != "" {
		cfg, err := readConfig(*conf)
		if err != nil {
			return err
		}
		given := false
		fs.Visit(func(f *flag.Flag) { given = given || f.Name == "data" })
		if v := cfg["data"]; v != "" && !given {
			*data = v
		}
	}
	if os.Geteuid() != 0 {
		return errors.New("run as root")
	}
	if fs.NArg() != 1 || !regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`).MatchString(fs.Arg(0)) {
		return errors.New("usage: cerberusttpd 2fa-reset [-data dir] <user>")
	}
	st, err := mfa.Open(*data)
	if err != nil {
		return err
	}
	if !st.Enrolled(fs.Arg(0)) {
		return fmt.Errorf("%s has no 2FA set up", fs.Arg(0))
	}
	if err := st.Reset(fs.Arg(0)); err != nil {
		return err
	}
	fmt.Printf("2FA for %s removed; they enrol again at next login\n", fs.Arg(0))
	return nil
}
