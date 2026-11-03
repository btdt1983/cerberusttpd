// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"syscall"

	"github.com/btdt1983/cerberusttpd/internal/helper"
)

// oidcEnabled reports whether single sign-on is configured (all or nothing,
// see checkOIDC).
func (o *options) oidcEnabled() bool { return o.oidcIssuer != "" }

// checkOIDC validates the single sign-on settings: either none or all of
// them, an https issuer that names one tenant, and an https callback URL.
func (o *options) checkOIDC() error {
	set := map[string]bool{"oidc-issuer": o.oidcIssuer != "", "oidc-client-id": o.oidcClientID != "",
		"oidc-client-secret-file": o.oidcSecretFile != "", "oidc-users": o.oidcUsers != "", "oidc-redirect-url": o.oidcRedirect != ""}
	n := 0
	for _, v := range set {
		if v {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	for _, k := range []string{"oidc-issuer", "oidc-client-id", "oidc-client-secret-file", "oidc-users", "oidc-redirect-url"} {
		if !set[k] {
			return fmt.Errorf("single sign-on needs all of oidc-issuer, oidc-client-id, oidc-client-secret-file, oidc-users and oidc-redirect-url: %s is missing", k)
		}
	}
	iss, err := url.Parse(o.oidcIssuer)
	if err != nil || iss.Scheme != "https" || iss.Host == "" {
		return fmt.Errorf("oidc-issuer must be an https URL, got %q", o.oidcIssuer)
	}
	if iss.Host == "login.microsoftonline.com" {
		first, _, _ := strings.Cut(strings.Trim(iss.Path, "/"), "/")
		switch strings.ToLower(first) {
		case "", "common", "organizations", "consumers":
			return fmt.Errorf("oidc-issuer must name your own tenant (https://login.microsoftonline.com/<tenant-id>/v2.0), not %q: sign-in must be limited to one organisation", first)
		}
	}
	red, err := url.Parse(o.oidcRedirect)
	if err != nil || red.Scheme != "https" || red.Host == "" || red.Path != "/oidc/callback" || red.RawQuery != "" || red.Fragment != "" {
		return fmt.Errorf("oidc-redirect-url must be https://<host>[:port]/oidc/callback, got %q", o.oidcRedirect)
	}
	return nil
}

// loadOIDC reads the client secret and returns the settings for the root
// process. The secret file must be ours alone; the users file is checked now
// so a mistake shows at start-up, and again at every login.
func (o *options) loadOIDC() (*helper.OIDC, error) {
	f, err := os.Open(o.oidcSecretFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 || fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must be owned by root and readable by root only (chmod 600)", o.oidcSecretFile)
	}
	raw := make([]byte, 4097)
	n, err := f.Read(raw)
	if err != nil && n == 0 {
		return nil, err
	}
	if n > 4096 {
		return nil, fmt.Errorf("%s: too large for a client secret", o.oidcSecretFile)
	}
	secret := strings.TrimSpace(string(raw[:n]))
	if secret == "" {
		return nil, errors.New(o.oidcSecretFile + " is empty")
	}
	if _, err := helper.LookupUser(o.oidcUsers, helper.Identity{}); err != nil {
		return nil, fmt.Errorf("oidc-users: %v", err)
	}
	return &helper.OIDC{Issuer: o.oidcIssuer, ClientID: o.oidcClientID, Secret: secret, UsersFile: o.oidcUsers, RedirectURL: o.oidcRedirect}, nil
}
