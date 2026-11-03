// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

// Package helper is the small root-side service: it authenticates users with
// PAM and TOTP, starts per-session file workers as that user, issues the TLS
// leaf certificate and tidies abandoned uploads. The network process asks; it
// never names a uid to act as.
package helper

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/btdt1983/cerberusttpd/internal/ipc"
	"github.com/btdt1983/cerberusttpd/internal/limiter"
	"github.com/btdt1983/cerberusttpd/internal/localca"
	"github.com/btdt1983/cerberusttpd/internal/mfa"
	"github.com/btdt1983/cerberusttpd/internal/pamauth"
	"github.com/btdt1983/cerberusttpd/internal/totp"
)

const (
	maxPassword = 512
	failFloor   = 3 * time.Second // failed logins all take this long (PAM adds ~2s only for real accounts)
	pendingTTL  = 5 * time.Minute
	maxMFAFails = 5
	totpIssuer  = "Cerberusttpd"
)

type Config struct {
	Exe         string // path to this binary, for starting workers
	PAMService  string
	MinUID      uint32
	Root        string // shared root for all users; empty means each user's home
	CA          *localca.CA
	MFA         *mfa.Store // nil disables 2FA
	DataDir     string
	StaleAfter  time.Duration // abandoned uploads older than this are removed
	OIDC        *OIDC         // single sign-on; nil disables it
	Scan        string        // virus scanner command for finished uploads; empty = none
	ScanTimeout time.Duration
}

type Request struct {
	Op       string `json:"op"` // login, mfa_setup, mfa_verify, leaf, oidc_begin, oidc_login
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
	RHost    string `json:"rhost,omitempty"`
	Pending  string `json:"pending,omitempty"`
	Code     string `json:"code,omitempty"`
	State    string `json:"state,omitempty"`    // oidc_begin: the browser's anti-forgery state
	Nonce    string `json:"nonce,omitempty"`    // oidc_begin, oidc_login
	Verifier string `json:"verifier,omitempty"` // oidc_begin, oidc_login: PKCE
	AuthCode string `json:"authcode,omitempty"` // oidc_login: the authorization code from the provider
}

type Response struct {
	OK       bool     `json:"ok"`
	Err      string   `json:"err,omitempty"` // denied, throttled, expired, unmapped, internal
	MFA      string   `json:"mfa,omitempty"` // "verify" or "enroll": password was right, a code is still needed
	Pending  string   `json:"pending,omitempty"`
	User     string   `json:"user,omitempty"`
	UID      uint32   `json:"uid,omitempty"`
	Admin    bool     `json:"admin,omitempty"`
	Secret   string   `json:"secret,omitempty"`
	URI      string   `json:"uri,omitempty"`
	Recovery []string `json:"recovery,omitempty"`
	Cert     []byte   `json:"cert,omitempty"`
	Key      []byte   `json:"key,omitempty"`
	CAPEM    []byte   `json:"ca,omitempty"`
	URL      string   `json:"url,omitempty"` // oidc_begin: where the browser signs in
	IdP      string   `json:"idp,omitempty"` // oidc_login: who the provider says it was (for the audit log)
}

// pending is a user who passed PAM but not yet the second factor. It lives only
// here; the network process holds an opaque token.
type pending struct {
	user    *user.User
	rhost   string
	secret  string // enrolment in progress
	fails   int
	expires time.Time
}

type server struct {
	Config
	limit *limiter.Login

	oidc *oidcClient

	mu      sync.Mutex
	pending map[string]*pending
	seen    map[string]time.Time // last login per user, for the upload cleanup
}

// Serve answers requests on f until the network process goes away.
func Serve(f *os.File, cfg Config) error {
	s := &server{Config: cfg, limit: limiter.NewLogin(), pending: map[string]*pending{}}
	if cfg.OIDC != nil {
		s.oidc = newOIDCClient(*cfg.OIDC)
	}
	go s.janitor()
	return ipc.Serve(f, func(raw json.RawMessage) (any, []*os.File) {
		var req Request
		if err := json.Unmarshal(raw, &req); err != nil {
			return Response{Err: "internal"}, nil
		}
		switch req.Op {
		case "login":
			return s.login(req)
		case "mfa_setup":
			return s.mfaSetup(req), nil
		case "mfa_verify":
			return s.mfaVerify(req)
		case "leaf":
			return s.leaf(), nil
		case "oidc_begin":
			return s.oidcBegin(req), nil
		case "oidc_login":
			return s.oidcLogin(req)
		}
		return Response{Err: "internal"}, nil
	})
}

func (s *server) leaf() Response {
	if s.CA == nil {
		return Response{Err: "internal"}
	}
	c, k, _, err := s.CA.IssueLeaf()
	if err != nil {
		log.Printf("helper: issue leaf: %v", err)
		return Response{Err: "internal"}
	}
	return Response{OK: true, Cert: c, Key: k, CAPEM: s.CA.RootPEM()}
}

func (s *server) login(req Request) (Response, []*os.File) {
	start := time.Now()
	fail := func(code string) (Response, []*os.File) {
		time.Sleep(time.Until(start.Add(failFloor)))
		return Response{Err: code}, nil
	}
	host := hostOnly(req.RHost)
	if ok, _ := s.limit.Allow(host, limiterKey(req.User)); !ok {
		return fail("throttled")
	}
	u, ok := s.eligible(req)
	if !ok {
		s.limit.Fail(host, limiterKey(req.User))
		return fail("denied")
	}
	if err := pamauth.Check(s.PAMService, u.Username, req.Password, host); err != nil {
		log.Printf("helper: login failed user=%q rhost=%s", u.Username, host)
		s.limit.Fail(host, limiterKey(req.User))
		return fail("denied")
	}
	if !s.homeOK(u) { // say so now, before asking for a second factor
		return Response{Err: "nohome", User: u.Username}, nil
	}
	if s.MFA == nil {
		s.limit.Success(host, limiterKey(req.User))
		return s.complete(u, host)
	}
	// Password is right; the worker is only started after the second factor.
	mode := "enroll"
	if s.MFA.Enrolled(u.Username) {
		mode = "verify"
	}
	return Response{OK: true, MFA: mode, User: u.Username, Pending: s.addPending(u, host)}, nil
}

func (s *server) addPending(u *user.User, host string) string {
	var raw [32]byte
	rand.Read(raw[:])
	tok := base64.RawURLEncoding.EncodeToString(raw[:])
	s.mu.Lock()
	s.pending[tok] = &pending{user: u, rhost: host, expires: time.Now().Add(pendingTTL)}
	s.mu.Unlock()
	return tok
}

// getPending returns the live pending login, or nil.
func (s *server) getPending(tok string) *pending {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pending[tok]
	if p != nil && time.Now().After(p.expires) {
		delete(s.pending, tok)
		return nil
	}
	return p
}

func (s *server) dropPending(tok string) {
	s.mu.Lock()
	delete(s.pending, tok)
	s.mu.Unlock()
}

// mfaSetup starts (or repeats) enrolment: a fresh secret kept only until the
// user proves their app has it.
func (s *server) mfaSetup(req Request) Response {
	p := s.getPending(req.Pending)
	if p == nil || s.MFA == nil || s.MFA.Enrolled(p.user.Username) {
		return Response{Err: "expired"}
	}
	s.mu.Lock()
	if p.secret == "" {
		p.secret = totp.NewSecret()
	}
	secret := p.secret
	s.mu.Unlock()
	return Response{OK: true, Secret: secret, URI: totp.URI(totpIssuer, p.user.Username, secret)}
}

func (s *server) mfaVerify(req Request) (Response, []*os.File) {
	p := s.getPending(req.Pending)
	if p == nil {
		return Response{Err: "expired"}, nil
	}
	name := p.user.Username
	if ok, _ := s.limit.Allow(p.rhost, limiterKey(name)); !ok {
		s.dropPending(req.Pending)
		return Response{Err: "throttled"}, nil
	}
	var recovery []string
	good := false
	if s.MFA.Enrolled(name) {
		good = s.MFA.Check(name, req.Code, time.Now())
	} else {
		s.mu.Lock()
		secret := p.secret
		s.mu.Unlock()
		if secret != "" {
			if step, ok := totp.Verify(secret, req.Code, time.Now(), 0); ok {
				var err error
				if recovery, err = s.MFA.Enroll(name, secret, step); err != nil {
					log.Printf("helper: store 2fa for %q: %v", name, err)
					return Response{Err: "internal"}, nil
				}
				good = true
				log.Printf("helper: 2fa enrolled user=%q", name)
			}
		}
	}
	if !good {
		log.Printf("helper: 2fa failed user=%q rhost=%s", name, p.rhost)
		s.limit.Fail(p.rhost, limiterKey(name))
		s.mu.Lock()
		p.fails++
		tooMany := p.fails >= maxMFAFails
		s.mu.Unlock()
		if tooMany {
			s.dropPending(req.Pending)
			return Response{Err: "expired"}, nil
		}
		return Response{Err: "denied"}, nil
	}
	s.dropPending(req.Pending)
	s.limit.Success(p.rhost, limiterKey(name))
	resp, files := s.complete(p.user, p.rhost)
	resp.Recovery = recovery
	return resp, files
}

// complete starts the user's worker and reports who logged in.
func (s *server) complete(u *user.User, host string) (Response, []*os.File) {
	if !s.homeOK(u) {
		return Response{Err: "nohome", User: u.Username}, nil
	}
	cred, admin, err := credFor(u)
	if err != nil {
		log.Printf("helper: credentials for %q: %v", u.Username, err)
		return Response{Err: "internal"}, nil
	}
	sock, err := s.startWorker(u, cred)
	if err != nil {
		log.Printf("helper: start worker for %q: %v", u.Username, err)
		return Response{Err: "internal"}, nil
	}
	s.noteSeen(u.Username)
	log.Printf("helper: login ok user=%q uid=%d admin=%v rhost=%s", u.Username, cred.Uid, admin, host)
	return Response{OK: true, User: u.Username, UID: cred.Uid, Admin: admin}, []*os.File{sock}
}

// homeOK reports whether the folder the user would see exists. Signing in
// does not open a PAM session, so an account that has never logged in on the
// console or over SSH (typical for Active Directory users) has no home yet;
// the worker would exit at once and the browser would bounce back to the
// sign-in page with no explanation.
func (s *server) homeOK(u *user.User) bool {
	root := s.rootFor(u)
	fi, err := os.Stat(root)
	if err != nil || !fi.IsDir() {
		log.Printf("helper: no folder for %q: %s does not exist or is not a directory", u.Username, root)
		return false
	}
	return true
}

// eligible validates the name shape and refuses root and system accounts.
func (s *server) eligible(req Request) (*user.User, bool) {
	if req.Password == "" || len(req.Password) > maxPassword {
		return nil, false
	}
	return s.eligibleName(req.User)
}

// eligibleName is the part of eligible that does not involve a password.
func (s *server) eligibleName(name string) (*user.User, bool) {
	if !ValidUser(name) {
		return nil, false
	}
	u, err := user.Lookup(name)
	if err != nil {
		return nil, false
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil || uid == 0 || uint32(uid) < s.MinUID {
		return nil, false
	}
	return u, true
}

// credFor builds the kernel credentials for u and reports wheel membership.
func credFor(u *user.User) (*syscall.Credential, bool, error) {
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, false, err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, false, err
	}
	gids, err := u.GroupIds()
	if err != nil {
		return nil, false, err
	}
	groups := []uint32{uint32(gid)}
	admin := false
	wheel, wheelErr := user.LookupGroup("wheel")
	for _, g := range gids {
		n, err := strconv.ParseUint(g, 10, 32)
		if err != nil {
			continue
		}
		if uint32(n) != uint32(gid) {
			groups = append(groups, uint32(n))
		}
		if wheelErr == nil && g == wheel.Gid {
			admin = true
		}
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groups}, admin, nil
}

func (s *server) rootFor(u *user.User) string {
	if s.Root != "" {
		return s.Root
	}
	return u.HomeDir
}

// cacheFor is where u's thumbnails are cached: always the user's own home, whatever
// the shared root is, so a read-only or shared root needs no special care.
func cacheFor(u *user.User) string {
	return filepath.Join(u.HomeDir, ".cache", "cerberusttpd", "thumbs")
}

// startWorker runs the file worker with cred and returns the network side of
// its socket. Dropping the socket makes the worker exit.
func (s *server) startWorker(u *user.User, cred *syscall.Credential) (*os.File, error) {
	mine, theirs, err := ipc.Pair()
	if err != nil {
		return nil, err
	}
	args := []string{"worker"}
	if s.Scan != "" {
		args = append(args, "-scan", s.Scan, "-scan-timeout", s.ScanTimeout.String())
	}
	cmd := exec.Command(s.Exe, append(args, s.rootFor(u), cacheFor(u))...)
	cmd.Dir = "/"
	cmd.Env = []string{}
	cmd.ExtraFiles = []*os.File{mine}
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	err = cmd.Start()
	mine.Close()
	if err != nil {
		theirs.Close()
		return nil, err
	}
	go func() {
		if err := cmd.Wait(); err != nil {
			log.Printf("helper: worker for %q ended: %v", u.Username, err)
		}
	}()
	return theirs, nil
}

func hostOnly(rhost string) string {
	if h, _, err := net.SplitHostPort(rhost); err == nil {
		return h
	}
	return rhost
}
