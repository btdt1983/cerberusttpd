// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// OIDC is the single sign-on setting (Microsoft Entra ID, or any OpenID
// Connect provider). All of it is decided here, in the root process: the
// network process only carries the browser's code, state and nonce, never
// sees the client secret and cannot name the user that gets logged in.
type OIDC struct {
	Issuer      string // https://login.microsoftonline.com/<tenant-id>/v2.0
	ClientID    string
	Secret      string // the client secret itself, read from a root-only file by `run`
	UsersFile   string // identity = unix user, one per line
	RedirectURL string // https://host/oidc/callback, registered with the provider
}

// outbound calls to the provider must never hold up a login for long
const oidcTimeout = 10 * time.Second

type oidcClient struct {
	cfg  OIDC
	http *http.Client

	mu   sync.Mutex // guards the lazily discovered provider
	ver  *oidc.IDTokenVerifier
	conf *oauth2.Config
}

func newOIDCClient(cfg OIDC) *oidcClient {
	return &oidcClient{cfg: cfg, http: &http.Client{Timeout: oidcTimeout}}
}

func (c *oidcClient) ctx(parent context.Context) context.Context {
	return oidc.ClientContext(parent, c.http)
}

// load discovers the provider on first use and keeps it only after a success,
// so the service starts, and keeps working for passwords, while the provider
// is unreachable.
func (c *oidcClient) load(parent context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conf != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(c.ctx(parent), oidcTimeout)
	defer cancel()
	p, err := oidc.NewProvider(ctx, c.cfg.Issuer)
	if err != nil {
		return err
	}
	// One fixed way to present the secret (in the form body, which Entra documents),
	// instead of oauth2's try-the-header-then-retry detection.
	ep := p.Endpoint()
	ep.AuthStyle = oauth2.AuthStyleInParams
	c.ver = p.Verifier(&oidc.Config{ClientID: c.cfg.ClientID, SupportedSigningAlgs: []string{oidc.RS256}})
	c.conf = &oauth2.Config{
		ClientID: c.cfg.ClientID, ClientSecret: c.cfg.Secret, Endpoint: ep,
		RedirectURL: c.cfg.RedirectURL, Scopes: []string{oidc.ScopeOpenID, "profile"},
	}
	return nil
}

// authURL is where the browser goes to sign in (authorization code + PKCE).
func (c *oidcClient) authURL(ctx context.Context, state, nonce, verifier string) (string, error) {
	if err := c.load(ctx); err != nil {
		return "", err
	}
	return c.conf.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)), nil
}

// Identity is who the provider says signed in.
type Identity struct {
	OID string // object id: stable, the recommended key
	UPN string // preferred_username: readable, but an admin can change it
}

func (i Identity) String() string {
	if i.UPN != "" {
		return i.UPN
	}
	return "oid:" + i.OID
}

var (
	errOIDCDenied = errors.New("sign-in refused")
	errOIDCDown   = errors.New("provider unavailable")
)

// identify trades the code for tokens and verifies the ID token: signature,
// issuer (which names the tenant), audience, expiry and the nonce this
// browser started with.
func (c *oidcClient) identify(parent context.Context, code, verifier, nonce string) (Identity, error) {
	if err := c.load(parent); err != nil {
		return Identity{}, fmt.Errorf("%w: %v", errOIDCDown, err)
	}
	ctx, cancel := context.WithTimeout(c.ctx(parent), oidcTimeout)
	defer cancel()
	tok, err := c.conf.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) && re.Response != nil && re.Response.StatusCode < 500 {
			return Identity{}, fmt.Errorf("%w: token request: %v", errOIDCDenied, err)
		}
		return Identity{}, fmt.Errorf("%w: %v", errOIDCDown, err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return Identity{}, fmt.Errorf("%w: no id_token", errOIDCDenied)
	}
	idt, err := c.ver.Verify(ctx, raw)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", errOIDCDenied, err)
	}
	if nonce == "" || idt.Nonce != nonce {
		return Identity{}, fmt.Errorf("%w: nonce mismatch", errOIDCDenied)
	}
	var cl struct {
		OID               string `json:"oid"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idt.Claims(&cl); err != nil {
		return Identity{}, fmt.Errorf("%w: %v", errOIDCDenied, err)
	}
	if cl.OID == "" && cl.PreferredUsername == "" {
		return Identity{}, fmt.Errorf("%w: token names no user", errOIDCDenied)
	}
	return Identity{OID: strings.ToLower(cl.OID), UPN: cl.PreferredUsername}, nil
}

// LookupUser finds the Unix account for an identity in the mapping file. Lines
// are "identity = unixuser"; an identity is a user name (jan@example.com, case
// does not matter) or oid:<object id>. The object id wins. The file is read on
// every login, so edits apply without a restart, and it must be ours: root
// owned and not writable by anyone else.
func LookupUser(path string, id Identity) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("%s must be owned by root and not writable by group or others", path)
	}
	var byOID, byUPN string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch {
		case id.OID != "" && k == "oid:"+id.OID:
			byOID = v
		case id.UPN != "" && k == strings.ToLower(id.UPN):
			byUPN = v
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	if byOID != "" {
		return byOID, nil
	}
	return byUPN, nil
}
