// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/btdt1983/cerberusttpd/internal/ipc"
	"github.com/btdt1983/cerberusttpd/internal/pamauth"
	"github.com/btdt1983/cerberusttpd/internal/worker"
)

// Share links give people without an account one file, for a limited time.
//
// Everything that matters is decided here, in the root process, never in the
// network process. The network process cannot name a user: a share is made
// with a grant that the helper handed out at that user's own login, and a
// download is answered with one file descriptor that the helper opened as
// the owner for the path it stored itself. A compromised network process
// therefore gets no more than the sessions it already holds.
const (
	shareMaxPerUser  = 100
	shareMaxUses     = 100000
	sharePasswordMax = 64 // bytes: bcrypt reads only the first 72
	grantLife        = maxLifeForGrants
	shareKeepAfter   = 24 * time.Hour // expired records stay visible this long
	shareFailFloor   = time.Second
	tokenMax         = 64
)

// maxLifeForGrants matches the longest a web session lives (12 hours).
const maxLifeForGrants = 12 * time.Hour

type shareRec struct {
	ID      string    `json:"id"`   // public handle for lists, revoking and the audit log
	Hash    string    `json:"hash"` // sha256 of the token; the token itself is never stored
	Owner   string    `json:"owner"`
	Path    string    `json:"path"` // relative to the owner's root
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
	PW      string    `json:"pw,omitempty"` // bcrypt
	Max     int       `json:"max,omitempty"`
	Used    int       `json:"used"`
}

// ShareInfo is what an owner sees about one of their shares.
type ShareInfo struct {
	ID      string    `json:"id"`
	Owner   string    `json:"owner,omitempty"` // only in the administrators' list
	Path    string    `json:"path"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
	Max     int       `json:"max,omitempty"`
	Used    int       `json:"used"`
	HasPW   bool      `json:"haspw,omitempty"`
}

type shareStore struct {
	mu   sync.Mutex
	file string
	m    map[string]*shareRec // by token hash
}

func loadShares(dir string) *shareStore {
	st := &shareStore{file: filepath.Join(dir, "shares.json"), m: map[string]*shareRec{}}
	b, err := os.ReadFile(st.file)
	if err != nil {
		return st
	}
	var recs []*shareRec
	if json.Unmarshal(b, &recs) != nil {
		log.Printf("helper: %s is unreadable, starting without shares", st.file)
		return st
	}
	for _, r := range recs {
		st.m[r.Hash] = r
	}
	return st
}

// saveLocked writes the whole list atomically. A crash must never lose a
// download counter or bring a revoked share back.
func (st *shareStore) saveLocked() error {
	recs := make([]*shareRec, 0, len(st.m))
	for _, r := range st.m {
		recs = append(recs, r)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Created.Before(recs[j].Created) })
	b, err := json.Marshal(recs)
	if err != nil {
		return err
	}
	tmp := st.file + ".tmp"
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
	return os.Rename(tmp, st.file)
}

func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// byToken finds a record without comparing secrets byte by byte: the map key
// is a hash of a 256-bit random token.
func (st *shareStore) byToken(token string) *shareRec {
	if token == "" || len(token) > tokenMax {
		return nil
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.m[tokenHash(token)]
}

// grant is what a login hands the network process: proof that one particular
// user signed in. It expires with the longest web session.
type grant struct {
	user    string
	admin   bool // decided by the helper at login (wheel), never by the network process
	expires time.Time
}

func (s *server) newGrant(user string, admin bool) string {
	var raw [32]byte
	rand.Read(raw[:])
	tok := base64.RawURLEncoding.EncodeToString(raw[:])
	s.mu.Lock()
	if s.grants == nil {
		s.grants = map[string]grant{}
	}
	s.grants[tokenHash(tok)] = grant{user: user, admin: admin, expires: time.Now().Add(grantLife)}
	s.mu.Unlock()
	return tok
}

// grantUser returns the user a live grant belongs to.
func (s *server) grantUser(tok string) (string, bool) {
	if tok == "" || len(tok) > tokenMax {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[tokenHash(tok)]
	if !ok || time.Now().After(g.expires) {
		return "", false
	}
	return g.user, true
}

// grantAdmin returns the user and whether the login that made the grant is an administrator.
func (s *server) grantAdmin(tok string) (string, bool, bool) {
	if tok == "" || len(tok) > tokenMax {
		return "", false, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[tokenHash(tok)]
	if !ok || time.Now().After(g.expires) {
		return "", false, false
	}
	return g.user, g.admin, true
}

func (s *server) dropGrant(tok string) {
	s.mu.Lock()
	delete(s.grants, tokenHash(tok))
	s.mu.Unlock()
}

// cleanSharePath turns what the owner picked into a root-relative file name,
// or "" when it cannot be a shareable file.
func cleanSharePath(p string) string {
	name := strings.TrimPrefix(path.Clean("/"+p), "/")
	if name == "" {
		return ""
	}
	for _, c := range strings.Split(name, "/") {
		if strings.HasPrefix(c, ".cerb-") {
			return ""
		}
	}
	return name
}

func (s *server) shareCreate(req Request) Response {
	if !s.Shares {
		return Response{Err: "disabled"}
	}
	owner, ok := s.grantUser(req.Grant)
	if !ok {
		return Response{Err: "denied"}
	}
	name := cleanSharePath(req.Path)
	ttl := time.Duration(req.TTL) * time.Second
	if name == "" || ttl <= 0 || ttl > s.ShareMaxTTL || req.Max < 0 || req.Max > shareMaxUses || len(req.Password) > sharePasswordMax {
		return Response{Err: "invalid"}
	}
	rec := &shareRec{Owner: owner, Path: name, Created: time.Now().UTC(), Expires: time.Now().Add(ttl).UTC(), Max: req.Max}
	if req.Password != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			return Response{Err: "internal"}
		}
		rec.PW = string(h)
	}
	var raw, id [32]byte
	rand.Read(raw[:])
	rand.Read(id[:])
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	rec.Hash, rec.ID = tokenHash(token), hex.EncodeToString(id[:6])

	st := s.shares
	st.mu.Lock()
	defer st.mu.Unlock()
	n := 0
	for _, r := range st.m {
		if r.Owner == owner && time.Now().Before(r.Expires) {
			n++
		}
	}
	if n >= shareMaxPerUser {
		return Response{Err: "toomany"}
	}
	st.m[rec.Hash] = rec
	if err := st.saveLocked(); err != nil {
		delete(st.m, rec.Hash)
		log.Printf("helper: save shares: %v", err)
		return Response{Err: "internal"}
	}
	log.Printf("helper: share created id=%s owner=%q expires=%s", rec.ID, owner, rec.Expires.Format(time.RFC3339))
	return Response{OK: true, Token: token, ShareID: rec.ID, Expires: rec.Expires}
}

func (s *server) shareList(req Request) Response {
	if !s.Shares {
		return Response{Err: "disabled"}
	}
	owner, admin, ok := s.grantAdmin(req.Grant)
	if !ok || (req.All && !admin) {
		return Response{Err: "denied"}
	}
	st := s.shares
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []ShareInfo
	for _, r := range st.m {
		if r.Owner == owner || req.All {
			out = append(out, ShareInfo{ID: r.ID, Owner: r.Owner, Path: r.Path, Created: r.Created, Expires: r.Expires, Max: r.Max, Used: r.Used, HasPW: r.PW != ""})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return Response{OK: true, Shares: out}
}

func (s *server) shareRevoke(req Request) Response {
	if !s.Shares {
		return Response{Err: "disabled"}
	}
	owner, admin, ok := s.grantAdmin(req.Grant)
	if !ok || (req.All && !admin) {
		return Response{Err: "denied"}
	}
	st := s.shares
	st.mu.Lock()
	defer st.mu.Unlock()
	for h, r := range st.m {
		if r.ID == req.ShareID && (r.Owner == owner || req.All) {
			delete(st.m, h)
			if err := st.saveLocked(); err != nil {
				st.m[h] = r
				log.Printf("helper: save shares: %v", err)
				return Response{Err: "internal"}
			}
			log.Printf("helper: share revoked id=%s owner=%q by=%q", r.ID, r.Owner, owner)
			return Response{OK: true, ShareID: r.ID}
		}
	}
	return Response{Err: "notfound"}
}

// usable says why a share cannot be used right now, or "" when it can.
func usable(r *shareRec, now time.Time) string {
	switch {
	case now.After(r.Expires):
		return "expired"
	case r.Max > 0 && r.Used >= r.Max:
		return "exhausted"
	}
	return ""
}

// shareInfo is what the public landing page may know without opening the file.
func (s *server) shareInfo(req Request) Response {
	if !s.Shares {
		return Response{Err: "unavailable", Detail: "disabled"}
	}
	r := s.shares.byToken(req.Token)
	if r == nil {
		return Response{Err: "unavailable", Detail: "unknown"}
	}
	s.shares.mu.Lock()
	why := usable(r, time.Now())
	resp := Response{OK: true, ShareID: r.ID, Name: path.Base(r.Path), Expires: r.Expires, HasPW: r.PW != ""}
	s.shares.mu.Unlock()
	if why != "" {
		return Response{Err: "unavailable", Detail: why, ShareID: r.ID}
	}
	return resp
}

// shareOpen answers a download: every check happens here, then the file is
// opened as its owner and passed on as a descriptor.
func (s *server) shareOpen(req Request) (Response, []*os.File) {
	if !s.Shares {
		return Response{Err: "unavailable", Detail: "disabled"}, nil
	}
	rec := s.shares.byToken(req.Token)
	if rec == nil {
		return Response{Err: "unavailable", Detail: "unknown"}, nil
	}
	id := rec.ID
	host := hostOnly(req.RHost)
	key := "share:" + id
	if ok, _ := s.shareLimit.Allow(host, key); !ok {
		return Response{Err: "throttled", ShareID: id}, nil
	}
	st := s.shares
	st.mu.Lock()
	why := usable(rec, time.Now())
	pw := rec.PW
	st.mu.Unlock()
	if why != "" {
		return Response{Err: "unavailable", Detail: why, ShareID: id}, nil
	}
	if pw != "" {
		if req.Password == "" {
			return Response{Err: "password", ShareID: id}, nil // asking for it is not a failure
		}
		start := time.Now()
		if len(req.Password) > sharePasswordMax || bcrypt.CompareHashAndPassword([]byte(pw), []byte(req.Password)) != nil {
			s.shareLimit.Fail(host, key)
			time.Sleep(time.Until(start.Add(shareFailFloor)))
			return Response{Err: "badpassword", ShareID: id}, nil
		}
	}
	select {
	case s.shareSem <- struct{}{}:
		defer func() { <-s.shareSem }()
	default:
		return Response{Err: "busy", ShareID: id}, nil
	}
	// The owner must still be allowed to exist: a locked, expired or deleted
	// account ends its shares too.
	u, ok := s.eligibleName(rec.Owner)
	if !ok || pamauth.Account(s.PAMService, u.Username, host) != nil || !s.homeOK(u) {
		log.Printf("helper: share %s refused: owner %q is not valid", id, rec.Owner)
		return Response{Err: "unavailable", Detail: "owner", ShareID: id}, nil
	}
	// Count before the file leaves, and keep the count on disk.
	count := countsAsDownload(rec.Max, req.Range)
	if count {
		st.mu.Lock()
		if why := usable(rec, time.Now()); why != "" {
			st.mu.Unlock()
			return Response{Err: "unavailable", Detail: why, ShareID: id}, nil
		}
		rec.Used++
		err := st.saveLocked()
		st.mu.Unlock()
		if err != nil {
			s.refund(rec)
			log.Printf("helper: save shares: %v", err)
			return Response{Err: "internal", ShareID: id}, nil
		}
	}
	resp, files := s.openAsOwner(u, rec)
	if resp.Err != "" {
		if count {
			s.refund(rec)
		}
		return resp, nil
	}
	resp.ShareID = id
	resp.Whole = rec.Max > 0
	return resp, files
}

// countsAsDownload says whether a request uses up one download. With a limit
// every request does and the file is always sent whole: a range request that
// "does not count" would let anyone fetch the file in pieces, or in one piece
// with a range such as 0-99999999, without ever using the limit. Links without
// a limit have nothing to count and keep resumable downloads.
func countsAsDownload(max int, rng string) bool {
	return max > 0 || rng == "" || rng == "bytes=0-"
}

func (s *server) refund(rec *shareRec) {
	s.shares.mu.Lock()
	if rec.Used > 0 {
		rec.Used--
	}
	s.shares.saveLocked()
	s.shares.mu.Unlock()
}

// openAsOwner starts a worker with the owner's credentials, has it open the
// stored path and lets the worker go again. Only a regular file qualifies.
func (s *server) openAsOwner(u *user.User, rec *shareRec) (Response, []*os.File) {
	cred, _, err := credFor(u)
	if err != nil {
		log.Printf("helper: share %s: credentials for %q: %v", rec.ID, u.Username, err)
		return Response{Err: "internal", ShareID: rec.ID}, nil
	}
	sock, err := s.startWorker(u, cred)
	if err != nil {
		log.Printf("helper: share %s: start worker for %q: %v", rec.ID, u.Username, err)
		return Response{Err: "internal", ShareID: rec.ID}, nil
	}
	wc, err := ipc.NewClient(sock)
	if err != nil {
		sock.Close()
		return Response{Err: "internal", ShareID: rec.ID}, nil
	}
	defer wc.Close() // the worker exits when its socket closes
	var wr worker.Response
	files, err := wc.Call(worker.Request{Op: "open", Path: rec.Path}, &wr)
	if err != nil {
		return Response{Err: "internal", ShareID: rec.ID}, nil
	}
	if wr.Err != "" || wr.Kind != "file" || len(files) != 1 {
		for _, f := range files {
			f.Close()
		}
		return Response{Err: "unavailable", Detail: "file", ShareID: rec.ID}, nil
	}
	return Response{OK: true, Name: path.Base(rec.Path), Size: wr.Size, MTime: wr.MTime}, files
}

// purgeShares forgets records that expired long enough ago.
func (s *server) purgeShares(now time.Time) {
	if s.shares == nil {
		return
	}
	st := s.shares
	st.mu.Lock()
	defer st.mu.Unlock()
	changed := false
	for h, r := range st.m {
		if now.After(r.Expires.Add(shareKeepAfter)) {
			delete(st.m, h)
			changed = true
		}
	}
	if changed {
		st.saveLocked()
	}
}

func (s *server) purgeGrants(now time.Time) {
	s.mu.Lock()
	for k, g := range s.grants {
		if now.After(g.expires) {
			delete(s.grants, k)
		}
	}
	s.mu.Unlock()
}
