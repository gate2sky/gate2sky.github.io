package web

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSigner(t *testing.T) {
	s := signer{key: []byte(strings.Repeat("k", 32))}
	type claims struct{ A string }
	tok := s.sign("one", claims{"x"}, time.Minute)

	var got claims
	if err := s.verify("one", tok, &got); err != nil || got.A != "x" {
		t.Fatalf("verify = %v, %+v", err, got)
	}
	if s.verify("two", tok, &got) == nil {
		t.Error("token accepted for another purpose")
	}
	if s.verify("one", tok[:len(tok)-2]+"AA", &got) == nil {
		t.Error("tampered token accepted")
	}
	other := signer{key: []byte(strings.Repeat("o", 32))}
	if other.verify("one", tok, &got) == nil {
		t.Error("token accepted with another key")
	}
	if s.verify("one", s.sign("one", claims{"x"}, -time.Second), &got) == nil {
		t.Error("expired token accepted")
	}
}

func TestNonceSet(t *testing.T) {
	n := newNonceSet()
	exp := time.Now().Add(time.Minute)
	if !n.use("a", exp) || n.use("a", exp) {
		t.Fatal("nonce reuse not detected")
	}
}

func TestLocalPath(t *testing.T) {
	for in, want := range map[string]string{
		"/x?y=1":            "/x?y=1",
		"":                  "/",
		"//evil.com":        "/",
		"/\\evil.com":       "/",
		"https://evil.com/": "/",
		"x":                 "/",
	} {
		if got := localPath(in); got != want {
			t.Errorf("localPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStripCookies(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Add("Cookie", "a=1; intergate-access=secret; b=\"2\"; intergate=session")
	r.Header.Add("Cookie", "intergate-access=again")
	stripCookies(r, "intergate-access", "intergate")
	if got := r.Header.Get("Cookie"); got != `a=1; b="2"` {
		t.Errorf("Cookie = %q", got)
	}
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", "intergate-access=x")
	stripCookies(r, "intergate-access")
	if _, ok := r.Header["Cookie"]; ok {
		t.Error("empty Cookie header left behind")
	}
}
