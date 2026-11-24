// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"testing"
)

// These tests use accounts every EL system has: root as a group member and
// nobody (uid 65534) as an ordinary recipient.

func peopleServer(t *testing.T, users bool, groups ...string) *server {
	s := testServer(t)
	s.Shares = false // sharing with people must work with links off
	s.ShareUsers, s.ShareGroups = users, groups
	s.acl = loadACL(s.DataDir)
	return s
}

func TestPeopleSetListStop(t *testing.T) {
	s := peopleServer(t, true, "root")
	jan := s.newGrant("jan", false)
	nob := s.newGrant("nobody", false)
	other := s.newGrant("kees", false)

	for name, req := range map[string]Request{
		"no recipient":      {Grant: jan, Path: "a.txt"},
		"no path":           {Grant: jan, Users: []string{"nobody"}},
		"part file":         {Grant: jan, Path: ".cerb-1.part", Users: []string{"nobody"}},
		"unknown user":      {Grant: jan, Path: "a.txt", Users: []string{"no-such-user-xyz"}},
		"root":              {Grant: jan, Path: "a.txt", Users: []string{"root"}},
		"myself":            {Grant: nob, Path: "a.txt", Users: []string{"nobody"}},
		"group not on list": {Grant: jan, Path: "a.txt", Groups: []string{"wheel"}},
	} {
		r := s.aclSet(req)
		if r.Err == "" {
			t.Errorf("%s: accepted", name)
		}
	}
	if r := s.aclSet(Request{Grant: "bogus", Path: "a.txt", Users: []string{"nobody"}}); r.Err != "denied" {
		t.Errorf("bad grant: %q", r.Err)
	}

	made := s.aclSet(Request{Grant: jan, Path: "../docs/a.txt", Users: []string{"nobody", "nobody"}})
	if made.Err != "" || made.ShareID == "" {
		t.Fatalf("set: %+v", made)
	}
	// Editing the same file keeps one record.
	again := s.aclSet(Request{Grant: jan, Path: "docs/a.txt", Users: []string{"nobody"}, Groups: []string{"root"}})
	if again.ShareID != made.ShareID {
		t.Errorf("a second record for the same file: %q vs %q", again.ShareID, made.ShareID)
	}
	if l := s.aclList(Request{Grant: jan}); len(l.People) != 1 || l.People[0].Path != "docs/a.txt" || len(l.People[0].Users) != 1 || len(l.People[0].Groups) != 1 {
		t.Fatalf("by me: %+v", l.People)
	}
	if l := s.aclList(Request{Grant: nob, With: true}); len(l.People) != 1 || l.People[0].Owner != "jan" {
		t.Fatalf("with nobody: %+v", l.People)
	}
	if l := s.aclList(Request{Grant: other, With: true}); len(l.People) != 0 {
		t.Fatalf("an outsider sees it: %+v", l.People)
	}
	if st := loadACL(s.DataDir); len(st.m) != 1 {
		t.Fatal("not persisted")
	}
	// The recipient cannot stop it; the owner can.
	if r := s.aclStop(Request{Grant: nob, ShareID: made.ShareID}); r.Err != "notfound" {
		t.Errorf("recipient stopped it: %+v", r)
	}
	if r := s.aclStop(Request{Grant: jan, ShareID: made.ShareID}); !r.OK {
		t.Errorf("owner stop: %+v", r)
	}
	if l := s.aclList(Request{Grant: nob, With: true}); len(l.People) != 0 {
		t.Error("still shared after stop")
	}
}

func TestPeopleGroupMembershipIsLive(t *testing.T) {
	s := peopleServer(t, false, "root")
	rec := &aclRec{ID: "x", Owner: "jan", Path: "a.txt", Groups: []string{"root"}}
	if !s.isRecipient(rec, "root") {
		t.Error("a member of the group is refused")
	}
	if s.isRecipient(rec, "nobody") {
		t.Error("a non-member is accepted")
	}
	if s.isRecipient(&aclRec{Owner: "root", Groups: []string{"root"}}, "root") {
		t.Error("the owner counts as a recipient")
	}
	// A group taken off the list in the config stops applying at once.
	s.ShareGroups = []string{"wheel"}
	if s.isRecipient(rec, "root") {
		t.Error("a group that is no longer allowed still applies")
	}
	// Named users need share-users on.
	named := &aclRec{ID: "y", Owner: "jan", Users: []string{"nobody"}}
	if s.isRecipient(named, "nobody") {
		t.Error("users are accepted while share-users is off")
	}
	s.ShareUsers = true
	if !s.isRecipient(named, "nobody") {
		t.Error("a named user is refused")
	}
}

func TestPeopleOffAndAdmin(t *testing.T) {
	s := peopleServer(t, false)
	g := s.newGrant("jan", false)
	if r := s.aclSet(Request{Grant: g, Path: "a", Users: []string{"nobody"}}); r.Err != "disabled" {
		t.Errorf("off: %q", r.Err)
	}
	if r, f := s.aclOpen(Request{Grant: g, ShareID: "x"}); r.Err != "disabled" || f != nil {
		t.Errorf("open while off: %+v", r)
	}
	s = peopleServer(t, true)
	jan, adm := s.newGrant("jan", false), s.newGrant("beheer", true)
	made := s.aclSet(Request{Grant: jan, Path: "a.txt", Users: []string{"nobody"}})
	if r := s.aclList(Request{Grant: jan, All: true}); r.Err != "denied" {
		t.Errorf("user listed all: %+v", r)
	}
	if r := s.aclStop(Request{Grant: jan, All: true, ShareID: made.ShareID}); r.Err != "denied" {
		t.Errorf("user stopped with all: %+v", r)
	}
	if l := s.aclList(Request{Grant: adm, All: true}); len(l.People) != 1 {
		t.Errorf("admin list: %+v", l.People)
	}
	if r := s.aclStop(Request{Grant: adm, All: true, ShareID: made.ShareID}); !r.OK {
		t.Errorf("admin stop: %+v", r)
	}
	// An outsider cannot open a share, and gets the same answer as for a missing one.
	made = s.aclSet(Request{Grant: jan, Path: "a.txt", Users: []string{"nobody"}})
	out := s.newGrant("kees", false)
	r1, _ := s.aclOpen(Request{Grant: out, ShareID: made.ShareID})
	r2, _ := s.aclOpen(Request{Grant: out, ShareID: "does-not-exist"})
	if r1.Err != "notfound" || r2.Err != "notfound" {
		t.Errorf("outsider: %q / %q", r1.Err, r2.Err)
	}
}
