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
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/btdt1983/cerberusttpd/internal/helper"
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
	addr, root, data, mode, names, domains, email, svcUser, pamService, twoFA, config                  string
	dnsProvider, dnsCreds, acmeCA, acmeHTTP, albums, shares, shareUsers, shareGroups                   string
	passwordLogin, shareRequirePW, adminGroup, loginGroup, oidcAutoDomains, createHome, createHomeBase string
	oidcIssuer, oidcClientID, oidcSecretFile, oidcUsers, oidcRedirect, oidcLabel                       string
	scanCommand                                                                                        string
	scanTimeout                                                                                        time.Duration
	shareMaxDays                                                                                       int

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
	fs.StringVar(&o.dnsProvider, "dns-provider", "", "acme: solve DNS-01 through this DNS provider (cloudflare or transip); empty = TLS-ALPN-01")
	fs.StringVar(&o.dnsCreds, "dns-credentials", "", "acme: root-only file with the DNS provider's credentials")
	fs.StringVar(&o.acmeHTTP, "acme-http-addr", "", "acme: answer HTTP-01 challenges on this local address (for example 127.0.0.1:8080) behind a reverse proxy that forwards /.well-known/acme-challenge/ from port 80")
	fs.StringVar(&o.acmeCA, "acme-ca", "production", "acme: production or staging (Let's Encrypt staging, for testing)")
	fs.StringVar(&o.svcUser, "user", "cerberusttpd", "unprivileged user for the network process")
	fs.StringVar(&o.pamService, "pam-service", "cerberusttpd", "PAM service name (/etc/pam.d/<name>)")
	fs.StringVar(&o.twoFA, "2fa", "required", "two-factor login: required (everyone enrols a TOTP app) or off")
	fs.StringVar(&o.albums, "albums", "on", "photo albums (masonry gallery, lightbox, album editor, thumbnails): on or off")
	fs.StringVar(&o.shares, "shares", "off", "share links for people without an account (one file, expiry, optional password and download limit): on or off")
	fs.StringVar(&o.shareUsers, "share-users", "off", "let users share files with chosen other users (read only): on or off")
	fs.StringVar(&o.shareGroups, "share-groups", "", "groups users may share files with, comma separated (empty = no sharing with groups)")
	fs.StringVar(&o.passwordLogin, "password-login", "on", "sign-in with a password (and the second factor): on or off; off needs single sign-on, nobody can then sign in while the provider is down")
	fs.StringVar(&o.shareRequirePW, "share-require-password", "off", "every share link must have a password: on or off")
	fs.StringVar(&o.adminGroup, "admin-group", "wheel", "members of this group are administrators (admin page); empty = nobody")
	fs.StringVar(&o.loginGroup, "login-group", "", "when set, only members of this group may sign in (password, single sign-on, and as recipient or owner of shares)")
	fs.StringVar(&o.oidcAutoDomains, "oidc-auto-domains", "", "single sign-on: sign in people who are not in the users file as the account named like their user name (jan@example.com), for these domains, comma separated")
	fs.StringVar(&o.createHome, "create-home", "off", "make a missing home directory at the first sign-in (skeleton, SELinux labels): on or off")
	fs.StringVar(&o.createHomeBase, "create-home-base", "/home", "create-home only creates homes below this directory")
	fs.IntVar(&o.shareMaxDays, "share-max-days", 30, "the longest a share link may stay valid, in days")
	fs.StringVar(&o.oidcIssuer, "oidc-issuer", "", "single sign-on: the provider, for Microsoft https://login.microsoftonline.com/<tenant-id>/v2.0")
	fs.StringVar(&o.oidcClientID, "oidc-client-id", "", "single sign-on: application (client) ID")
	fs.StringVar(&o.oidcSecretFile, "oidc-client-secret-file", "", "single sign-on: root-only file holding the client secret")
	fs.StringVar(&o.oidcUsers, "oidc-users", "", "single sign-on: root-owned file mapping identities to Unix users (jan@example.com = jan)")
	fs.StringVar(&o.oidcRedirect, "oidc-redirect-url", "", "single sign-on: https://<host>[:port]/oidc/callback, as registered with the provider")
	fs.StringVar(&o.oidcLabel, "oidc-label", "Microsoft", "single sign-on: name on the sign-in button")
	fs.StringVar(&o.scanCommand, "scan-command", "", "virus scanner run on every finished upload: absolute path plus arguments, the file is added last (clamscan exit codes: 0 clean, 1 infected)")
	fs.DurationVar(&o.scanTimeout, "scan-timeout", 5*time.Minute, "give up on a scan after this long (the upload is then refused)")
	fs.Int64Var(&o.maxUpload, "max-upload", 20<<30, "largest allowed upload in bytes (0 = unlimited)")
	fs.DurationVar(&o.staleAfter, "stale-after", 7*24*time.Hour, "remove abandoned uploads untouched for this long (0 = never)")
	fs.UintVar(&o.minUID, "min-uid", 1000, "lowest uid allowed to log in")
}

func (o *options) args() []string {
	return []string{
		"-addr", o.addr, "-root", o.root, "-data", o.data, "-tls", o.mode,
		"-names", o.names, "-domain", o.domains, "-acme-email", o.email,
		"-dns-provider", o.dnsProvider, "-acme-ca", o.acmeCA, "-acme-http-addr", o.acmeHTTP,
		"-user", o.svcUser, "-pam-service", o.pamService, "-min-uid", fmt.Sprint(o.minUID),
		"-2fa", o.twoFA, "-albums", o.albums, "-scan-command", o.scanCommand, "-password-login", o.passwordLogin, "-share-require-password", o.shareRequirePW, "-admin-group", o.adminGroup, "-login-group", o.loginGroup, "-oidc-auto-domains", o.oidcAutoDomains, "-create-home", o.createHome, "-create-home-base", o.createHomeBase, "-shares", o.shares, "-share-users", o.shareUsers, "-share-groups", o.shareGroups, "-share-max-days", fmt.Sprint(o.shareMaxDays), "-oidc-issuer", o.oidcIssuer, "-oidc-label", o.oidcLabel, "-max-upload", fmt.Sprint(o.maxUpload), "-stale-after", o.staleAfter.String(),
	}
}

// resolve fills in what a domain implies, like Caddy: a domain means a public
// certificate (tls=acme) on :443, unless tls or addr were set explicitly.
// Call it after the command line and the config file have been applied.
func (o *options) resolve(fs *flag.FlagSet) error {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if o.domains != "" && !set["tls"] {
		o.mode = "acme"
	}
	if o.domains != "" && o.mode != "acme" {
		return fmt.Errorf("domain needs tls = acme (it is %q)", o.mode)
	}
	if o.albums != "on" && o.albums != "off" {
		return fmt.Errorf("albums must be on or off (it is %q)", o.albums)
	}
	if o.shares != "on" && o.shares != "off" {
		return fmt.Errorf("shares must be on or off (it is %q)", o.shares)
	}
	if o.shareUsers != "on" && o.shareUsers != "off" {
		return fmt.Errorf("share-users must be on or off (it is %q)", o.shareUsers)
	}
	if _, err := o.shareGroupList(); err != nil {
		return err
	}
	for name, v := range map[string]string{"password-login": o.passwordLogin, "share-require-password": o.shareRequirePW, "create-home": o.createHome} {
		if v != "on" && v != "off" {
			return fmt.Errorf("%s must be on or off (it is %q)", name, v)
		}
	}
	for name, v := range map[string]string{"admin-group": o.adminGroup, "login-group": o.loginGroup} {
		if v != "" && !helper.ValidUser(v) {
			return fmt.Errorf("%s: %q is not a valid group name", name, v)
		}
	}
	if o.passwordLogin == "off" && !o.oidcEnabled() {
		return errors.New("password-login = off needs single sign-on (oidc-*), otherwise nobody could sign in")
	}
	if _, err := o.autoDomainList(); err != nil {
		return err
	}
	if o.oidcAutoDomains != "" && !o.oidcEnabled() {
		return errors.New("oidc-auto-domains needs single sign-on (oidc-*)")
	}
	if b := o.createHomeBase; !strings.HasPrefix(b, "/") || filepath.Clean(b) != b || b == "/" {
		return fmt.Errorf("create-home-base must be an absolute path other than /, without a trailing slash (it is %q)", b)
	}
	if o.shareMaxDays < 1 || o.shareMaxDays > 3650 {
		return fmt.Errorf("share-max-days must be between 1 and 3650 (it is %d)", o.shareMaxDays)
	}
	if err := o.checkOIDC(); err != nil {
		return err
	}
	if o.acmeHTTP != "" && o.dnsProvider != "" {
		return errors.New("acme-http-addr and dns-provider are alternatives: set only one")
	}
	if o.mode == "acme" && !set["addr"] && o.acmeHTTP == "" {
		o.addr = ":443"
	}
	return nil
}

// shareGroupList parses share-groups: names of groups, comma separated.
func (o *options) shareGroupList() ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, g := range strings.Split(o.shareGroups, ",") {
		if g = strings.TrimSpace(g); g == "" || seen[g] {
			continue
		}
		if !helper.ValidUser(g) {
			return nil, fmt.Errorf("share-groups: %q is not a valid group name", g)
		}
		seen[g] = true
		out = append(out, g)
	}
	return out, nil
}

// autoDomainList parses oidc-auto-domains.
func (o *options) autoDomainList() ([]string, error) {
	var out []string
	for _, d := range strings.Split(o.oidcAutoDomains, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if !domainRE.MatchString(d) {
			return nil, fmt.Errorf("oidc-auto-domains: %q is not a domain name", d)
		}
		out = append(out, d)
	}
	return out, nil
}

var domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
