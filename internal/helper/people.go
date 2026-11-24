// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/btdt1983/cerberusttpd/internal/pamauth"
)

// Sharing a file with chosen users or groups. Like a share link, but for
// people who have an account: the recipient is always the user the login grant
// belongs to, never a name from the request, and a download is answered with
// one file opened by the helper as the owner. Group membership is looked up
// again on every request, so removing someone from a group takes effect at
// once. Read-only, one file per record.
const (
	peopleMaxPerOwner = 200
	peopleMaxUsers    = 50
	peopleMaxGroups   = 20
)

type aclRec struct {
	ID      string    `json:"id"`
	Owner   string    `json:"owner"`
	Path    string    `json:"path"`
	Users   []string  `json:"users,omitempty"`
	Groups  []string  `json:"groups,omitempty"`
	Created time.Time `json:"created"`
}

// PeopleInfo is what the API shows about one record.
type PeopleInfo struct {
	ID      string    `json:"id"`
	Owner   string    `json:"owner"`
	Path    string    `json:"path"`
	Users   []string  `json:"users,omitempty"`
	Groups  []string  `json:"groups,omitempty"`
	Created time.Time `json:"created"`
}

type aclStore struct {
	mu   sync.Mutex
	file string
	m    map[string]*aclRec // by ID
}

func loadACL(dir string) *aclStore {
	st := &aclStore{file: filepath.Join(dir, "shared.json"), m: map[string]*aclRec{}}
	b, err := os.ReadFile(st.file)
	if err != nil {
		return st
	}
	var recs []*aclRec
	if json.Unmarshal(b, &recs) != nil {
		log.Printf("helper: %s is unreadable, starting without shared files", st.file)
		return st
	}
	for _, r := range recs {
		st.m[r.ID] = r
	}
	return st
}

func (st *aclStore) saveLocked() error {
	recs := make([]*aclRec, 0, len(st.m))
	for _, r := range st.m {
		recs = append(recs, r)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Created.Before(recs[j].Created) })
	b, err := json.Marshal(recs)
	if err != nil {
		return err
	}
	return writeAtomic(st.file, b)
}

// writeAtomic replaces file with b, so a crash never leaves half a list.
func writeAtomic(file string, b []byte) error {
	tmp := file + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, file)
}

// internalOn says whether sharing with people is switched on at all.
func (s *server) internalOn() bool { return s.ShareUsers || len(s.ShareGroups) > 0 }

// sharingOn says whether any kind of sharing is on.
func (s *server) sharingOn() bool { return s.Shares || s.internalOn() }

func (s *server) groupAllowed(g string) bool {
	for _, a := range s.ShareGroups {
		if a == g {
			return true
		}
	}
	return false
}

// isRecipient reports whether user name may open rec, using the group
// membership as it is right now.
func (s *server) isRecipient(rec *aclRec, name string) bool {
	if rec.Owner == name {
		return false
	}
	for _, u := range rec.Users {
		if u == name {
			return s.ShareUsers
		}
	}
	if len(rec.Groups) == 0 {
		return false
	}
	u, err := user.Lookup(name)
	if err != nil {
		return false
	}
	gids, err := u.GroupIds()
	if err != nil {
		return false
	}
	mine := map[string]bool{}
	for _, g := range gids {
		mine[g] = true
	}
	for _, gn := range rec.Groups {
		if !s.groupAllowed(gn) {
			continue // dropped from the list in the config: the share no longer applies
		}
		if g, err := user.LookupGroup(gn); err == nil && mine[g.Gid] {
			return true
		}
	}
	return false
}

func info(r *aclRec) PeopleInfo {
	return PeopleInfo{ID: r.ID, Owner: r.Owner, Path: r.Path, Users: r.Users, Groups: r.Groups, Created: r.Created}
}

// aclSet creates or replaces the share of one file for its owner.
func (s *server) aclSet(req Request) Response {
	if !s.internalOn() {
		return Response{Err: "disabled"}
	}
	owner, ok := s.grantUser(req.Grant)
	if !ok {
		return Response{Err: "denied"}
	}
	name := cleanSharePath(req.Path)
	if name == "" || len(req.Users) > peopleMaxUsers || len(req.Groups) > peopleMaxGroups || (len(req.Users) == 0 && len(req.Groups) == 0) {
		return Response{Err: "invalid"}
	}
	if len(req.Users) > 0 && !s.ShareUsers {
		return Response{Err: "invalid"}
	}
	var users, groups []string
	seen := map[string]bool{}
	for _, n := range req.Users {
		u, ok := s.eligibleName(n)
		if !ok || u.Username == owner {
			return Response{Err: "recipient"} // one answer for unknown, not allowed and yourself
		}
		if !seen[u.Username] {
			seen[u.Username] = true
			users = append(users, u.Username)
		}
	}
	for _, g := range req.Groups {
		if _, err := user.LookupGroup(g); err != nil || !s.groupAllowed(g) {
			return Response{Err: "recipient"}
		}
		if !seen["g:"+g] {
			seen["g:"+g] = true
			groups = append(groups, g)
		}
	}
	st := s.acl
	st.mu.Lock()
	defer st.mu.Unlock()
	var rec *aclRec
	n := 0
	for _, r := range st.m {
		if r.Owner == owner {
			n++
			if r.Path == name {
				rec = r
			}
		}
	}
	if rec == nil {
		if n >= peopleMaxPerOwner {
			return Response{Err: "toomany"}
		}
		var id [6]byte
		rand.Read(id[:])
		rec = &aclRec{ID: hex.EncodeToString(id[:]), Owner: owner, Path: name, Created: time.Now().UTC()}
	}
	old := *rec
	rec.Users, rec.Groups = users, groups
	st.m[rec.ID] = rec
	if err := st.saveLocked(); err != nil {
		if old.ID == "" {
			delete(st.m, rec.ID)
		} else {
			*rec = old
		}
		log.Printf("helper: save shared files: %v", err)
		return Response{Err: "internal"}
	}
	log.Printf("helper: shared id=%s owner=%q users=%v groups=%v", rec.ID, owner, users, groups)
	return Response{OK: true, ShareID: rec.ID}
}

// aclList answers "shared by me" (mine), "shared with me" (with), or for an
// administrator everything (all).
func (s *server) aclList(req Request) Response {
	if !s.internalOn() {
		return Response{Err: "disabled"}
	}
	me, admin, ok := s.grantAdmin(req.Grant)
	if !ok || (req.All && !admin) {
		return Response{Err: "denied"}
	}
	st := s.acl
	st.mu.Lock()
	recs := make([]*aclRec, 0, len(st.m))
	for _, r := range st.m {
		recs = append(recs, r)
	}
	st.mu.Unlock()
	var out []PeopleInfo
	for _, r := range recs {
		switch {
		case req.All:
			out = append(out, info(r))
		case req.With && s.isRecipient(r, me):
			out = append(out, info(r))
		case !req.With && r.Owner == me:
			out = append(out, info(r))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return Response{OK: true, People: out}
}

func (s *server) aclStop(req Request) Response {
	if !s.internalOn() {
		return Response{Err: "disabled"}
	}
	me, admin, ok := s.grantAdmin(req.Grant)
	if !ok || (req.All && !admin) {
		return Response{Err: "denied"}
	}
	st := s.acl
	st.mu.Lock()
	defer st.mu.Unlock()
	r := st.m[req.ShareID]
	if r == nil || (r.Owner != me && !req.All) {
		return Response{Err: "notfound"}
	}
	delete(st.m, r.ID)
	if err := st.saveLocked(); err != nil {
		st.m[r.ID] = r
		log.Printf("helper: save shared files: %v", err)
		return Response{Err: "internal"}
	}
	log.Printf("helper: share stopped id=%s owner=%q by=%q", r.ID, r.Owner, me)
	return Response{OK: true, ShareID: r.ID}
}

// aclOpen hands a recipient the file: one descriptor, opened as the owner.
func (s *server) aclOpen(req Request) (Response, []*os.File) {
	if !s.internalOn() {
		return Response{Err: "disabled"}, nil
	}
	me, ok := s.grantUser(req.Grant)
	if !ok {
		return Response{Err: "denied"}, nil
	}
	st := s.acl
	st.mu.Lock()
	rec := st.m[req.ShareID]
	st.mu.Unlock()
	if rec == nil || !s.isRecipient(rec, me) {
		return Response{Err: "notfound"}, nil // the same answer whether it exists or not
	}
	owner, ok := s.eligibleName(rec.Owner)
	if !ok || pamauth.Account(s.PAMService, owner.Username, "") != nil || !s.homeOK(owner) {
		log.Printf("helper: shared file %s refused: owner %q is not valid", rec.ID, rec.Owner)
		return Response{Err: "unavailable", ShareID: rec.ID}, nil
	}
	select {
	case s.shareSem <- struct{}{}:
		defer func() { <-s.shareSem }()
	default:
		return Response{Err: "busy", ShareID: rec.ID}, nil
	}
	resp, files := s.openAsOwner(owner, &shareRec{ID: rec.ID, Path: rec.Path})
	resp.ShareID = rec.ID
	if resp.Err == "" {
		resp.Owner = rec.Owner
	}
	return resp, files
}
