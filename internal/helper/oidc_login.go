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
	name, err := LookupUser(s.OIDC.UsersFile, id)
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
	s.limit.Success(host, "oidc")
	resp, files := s.complete(u, host)
	resp.IdP = idp
	return resp, files
}
