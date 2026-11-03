// Copyright (C) 2026 David Bauer
// SPDX-License-Identifier: AGPL-3.0-only

package helper

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"
)

// idp is a fake provider: discovery and keys from go-oidc's test server, plus
// a token endpoint that hands out whatever ID token the test set up.
type idp struct {
	srv     *httptest.Server
	key     *rsa.PrivateKey
	other   *rsa.PrivateKey
	claims  func() string // JSON claims of the next ID token
	signer  any
	alg     string
	status  int // token endpoint status; 0 = 200
	lastReq url.Values
}

func newIdP(t *testing.T) *idp {
	t.Helper()
	i := &idp{alg: oidc.RS256}
	var err error
	if i.key, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	if i.other, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	i.signer = i.key
	o := &oidctest.Server{PublicKeys: []oidctest.PublicKey{{PublicKey: i.key.Public(), KeyID: "k1", Algorithm: oidc.RS256}}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		i.lastReq = r.PostForm
		if r.PostForm.Get("code") != "good-code" {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		if i.status != 0 {
			http.Error(w, "boom", i.status)
			return
		}
		tok := oidctest.SignIDToken(i.signer, "k1", i.alg, i.claims())
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"a","token_type":"Bearer","id_token":%q}`, tok)
	})
	mux.Handle("/", o)
	i.srv = httptest.NewServer(mux)
	o.SetIssuer(i.srv.URL)
	t.Cleanup(i.srv.Close)
	return i
}

func (i *idp) client(secretFile string) *oidcClient {
	return newOIDCClient(OIDC{Issuer: i.srv.URL, ClientID: "cid", Secret: "s3cret",
		UsersFile: secretFile, RedirectURL: "https://files.example.com/oidc/callback"})
}

func (i *idp) tokenClaims(mod map[string]any) func() string {
	return func() string {
		m := map[string]any{"iss": i.srv.URL, "aud": "cid", "sub": "x", "exp": time.Now().Add(time.Hour).Unix(),
			"nonce": "n1", "oid": "AAAA-bbbb", "preferred_username": "Jan@Example.com"}
		for k, v := range mod {
			if v == nil {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		s := "{"
		first := true
		for k, v := range m {
			if !first {
				s += ","
			}
			first = false
			s += fmt.Sprintf("%q:%s", k, jsonVal(v))
		}
		return s + "}"
	}
}

func jsonVal(v any) string {
	switch x := v.(type) {
	case string:
		return fmt.Sprintf("%q", x)
	default:
		return fmt.Sprint(x)
	}
}

func TestIdentifyAcceptsAGoodToken(t *testing.T) {
	p := newIdP(t)
	p.claims = p.tokenClaims(nil)
	id, err := p.client("").identify(context.Background(), "good-code", "the-verifier", "n1")
	if err != nil {
		t.Fatal(err)
	}
	if id.OID != "aaaa-bbbb" || id.UPN != "Jan@Example.com" {
		t.Errorf("%+v", id)
	}
	f := p.lastReq
	if f.Get("client_id") != "cid" || f.Get("client_secret") != "s3cret" || f.Get("code_verifier") != "the-verifier" ||
		f.Get("grant_type") != "authorization_code" || f.Get("redirect_uri") != "https://files.example.com/oidc/callback" {
		t.Errorf("token request %v", f)
	}
}

func TestIdentifyRefusesBadTokens(t *testing.T) {
	past := time.Now().Add(-time.Hour).Unix()
	cases := map[string]struct {
		mod    map[string]any
		nonce  string
		code   string
		signer func(*idp)
		status int
		down   bool
	}{
		"wrong nonce":      {nonce: "other"},
		"empty nonce":      {nonce: ""},
		"wrong audience":   {mod: map[string]any{"aud": "someone-else"}, nonce: "n1"},
		"wrong issuer":     {mod: map[string]any{"iss": "https://evil.example"}, nonce: "n1"},
		"expired":          {mod: map[string]any{"exp": past}, nonce: "n1"},
		"foreign key":      {signer: func(i *idp) { i.signer = i.other }, nonce: "n1"},
		"hmac not rsa":     {signer: func(i *idp) { i.alg, i.signer = "HS256", []byte("0123456789abcdef0123456789abcdef") }, nonce: "n1"},
		"no user in token": {mod: map[string]any{"oid": nil, "preferred_username": nil}, nonce: "n1"},
		"bad code":         {code: "bad-code", nonce: "n1"},
		"provider error":   {status: 500, nonce: "n1", down: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := newIdP(t)
			p.claims = p.tokenClaims(c.mod)
			p.status = c.status
			if c.signer != nil {
				c.signer(p)
			}
			code := c.code
			if code == "" {
				code = "good-code"
			}
			_, err := p.client("").identify(context.Background(), code, "v", c.nonce)
			if err == nil {
				t.Fatal("accepted")
			}
			if got := errors.Is(err, errOIDCDown); got != c.down {
				t.Errorf("provider-down=%v want %v (%v)", got, c.down, err)
			}
		})
	}
}

func TestProviderUnreachableIsNotADenial(t *testing.T) {
	p := newIdP(t)
	c := p.client("")
	p.srv.Close()
	_, err := c.identify(context.Background(), "good-code", "v", "n1")
	if !errors.Is(err, errOIDCDown) {
		t.Fatalf("got %v", err)
	}
}

func TestAuthURL(t *testing.T) {
	p := newIdP(t)
	u, err := p.client("").authURL(context.Background(), "st", "no", "ver")
	if err != nil {
		t.Fatal(err)
	}
	pu, err := url.Parse(u)
	if err != nil || !strings.HasPrefix(u, p.srv.URL+"/auth?") {
		t.Fatalf("%q %v", u, err)
	}
	q := pu.Query()
	want := map[string]string{"response_type": "code", "client_id": "cid", "state": "st", "nonce": "no",
		"code_challenge_method": "S256", "scope": "openid profile", "redirect_uri": "https://files.example.com/oidc/callback"}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q want %q", k, q.Get(k), v)
		}
	}
	if q.Get("code_challenge") == "" || strings.Contains(u, "s3cret") || strings.Contains(u, "ver&") {
		t.Errorf("challenge/secret handling: %s", u)
	}
}

func writeUsers(t *testing.T, mode os.FileMode, body string) string {
	p := filepath.Join(t.TempDir(), "oidc-users")
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLookupUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the users file must be root-owned; run as root")
	}
	f := writeUsers(t, 0o600, "# comment\n\nJan@Example.com = jan\noid:aaaa-bbbb = jan2\npiet@example.com=piet\nbad line\n")
	for _, c := range []struct {
		id   Identity
		want string
	}{
		{Identity{UPN: "jan@example.COM"}, "jan"},                    // case does not matter
		{Identity{UPN: "jan@example.com", OID: "aaaa-bbbb"}, "jan2"}, // the object id wins
		{Identity{UPN: "piet@example.com", OID: "zzzz"}, "piet"},
		{Identity{UPN: "nobody@example.com"}, ""},
		{Identity{OID: "aaaa-bbbb"}, "jan2"},
		{Identity{}, ""},
	} {
		got, err := LookupUser(f, c.id)
		if err != nil || got != c.want {
			t.Errorf("%+v: %q, %v (want %q)", c.id, got, err, c.want)
		}
	}
	for name, mode := range map[string]os.FileMode{"group-writable": 0o660, "world-writable": 0o666} {
		if _, err := LookupUser(writeUsers(t, mode, "jan@example.com = jan\n"), Identity{UPN: "jan@example.com"}); err == nil {
			t.Errorf("%s file accepted", name)
		}
	}
	if _, err := LookupUser(filepath.Join(t.TempDir(), "missing"), Identity{UPN: "a"}); err == nil {
		t.Error("missing file is not an error")
	}
}

func TestMappedAccountsStillNeedToBeOrdinaryUsers(t *testing.T) {
	s := &server{Config: Config{MinUID: 1000}}
	for _, name := range []string{"root", "", "../etc", "Jan Smith", "no-such-user-xyz", strings.Repeat("a", 40)} {
		if _, ok := s.eligibleName(name); ok {
			t.Errorf("%q accepted", name)
		}
	}
	s.MinUID = 1 << 31 // nobody (65534) is below this
	if _, ok := s.eligibleName("nobody"); ok {
		t.Error("a uid below min-uid accepted")
	}
}
