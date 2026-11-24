// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"errors"
	"log"
	"os"

	"github.com/btdt1983/cerberusttpd/internal/pamauth"
)

// oidcBegin returns the provider's sign-in URL for a state, nonce and PKCE
// verifier the network process made up for this browser.
func (s *server) oidcBegin(req Request) Response {
	if s.oidc == nil || req.State == "" || req.Nonce == "" || req.Verifier == "" {
		return Response{Err: "internal"}
	}
	u, err := s.oidc.authURL(context.Background(), req.State, req.Nonce, req.Verifier)
	if err != nil {
		log.Printf("helper: oidc discovery: %v", err)
		return Response{Err: "internal"}
	}
	return Response{OK: true, URL: u}
}

// oidcLogin completes a single sign-on: it verifies the provider's answer,
// maps the identity to a Unix account through the users file and starts that
// user's worker, with the same checks as a password login (no root, no system
// accounts, PAM account management). Single sign-on replaces both the password
// and the second factor: the provider has asked for those.
func (s *server) oidcLogin(req Request) (Response, []*os.File) {
	if s.oidc == nil {
		return Response{Err: "internal"}, nil
	}
	host := hostOnly(req.RHost)
	if ok, _ := s.limit.Allow(host, "oidc"); !ok {
		return Response{Err: "throttled"}, nil
	}
	id, err := s.oidc.identify(context.Background(), req.AuthCode, req.Verifier, req.Nonce)
	if err != nil {
		log.Printf("helper: oidc login failed rhost=%s: %v", host, err)
		if errors.Is(err, errOIDCDenied) {
			s.limit.Fail(host, "oidc")
			return Response{Err: "denied"}, nil
		}
		return Response{Err: "internal"}, nil
	}
	idp := id.String()
	name, auto, err := s.mapIdentity(id)
	if err != nil {
		log.Printf("helper: oidc users file: %v", err)
		return Response{Err: "internal", IdP: idp}, nil
	}
	u, ok := s.eligibleName(name)
	if name == "" || !ok {
		log.Printf("helper: oidc login refused idp=%q: no usable account (mapped to %q)", idp, name)
		s.limit.Fail(host, "oidc")
		return Response{Err: "unmapped", IdP: idp}, nil
	}
	if err := pamauth.Account(s.PAMService, u.Username, host); err != nil {
		log.Printf("helper: oidc login refused idp=%q user=%q: account not valid", idp, u.Username)
		return Response{Err: "denied", User: u.Username, IdP: idp}, nil
	}
	if auto && !s.pinOID(u.Username, id.OID) {
		log.Printf("helper: oidc login refused idp=%q user=%q: the account is linked to a different person (object id)", idp, u.Username)
		s.limit.Fail(host, "oidc")
		return Response{Err: "mismatch", User: u.Username, IdP: idp}, nil
	}
	s.limit.Success(host, "oidc")
	resp, files := s.complete(u, host)
	if resp.Err == "nohome" {
		resp.IdP = idp
		return resp, nil
	}
	resp.IdP = idp
	return resp, files
}

// mapIdentity decides which account an identity signs in as. The users file has
// the last word: an entry there, even a "-" that refuses the person, is used
// instead of automatic mapping. Only an identity without any entry may be
// mapped automatically, and only for the domains that were listed.
func (s *server) mapIdentity(id Identity) (name string, auto bool, err error) {
	name, err = LookupUser(s.OIDC.UsersFile, id)
	if err != nil || name != "" || len(s.OIDC.AutoDomains) == 0 {
		return name, false, err
	}
	if name = autoName(id.UPN, s.OIDC.AutoDomains); name != "" {
		return name, true, nil
	}
	return "", false, nil
}
