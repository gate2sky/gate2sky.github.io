package web

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
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
	r.Header.Add("Cookie", "a=1; securegate-access=secret; b=\"2\"; securegate=session")
	r.Header.Add("Cookie", "securegate-access=again")
	stripCookies(r, "securegate-access", "securegate")
	if got := r.Header.Get("Cookie"); got != `a=1; b="2"` {
		t.Errorf("Cookie = %q", got)
	}
	r = httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", "securegate-access=x")
	stripCookies(r, "securegate-access")
	if _, ok := r.Header["Cookie"]; ok {
		t.Error("empty Cookie header left behind")
	}
}

func authorizedKey(t *testing.T, pub any, comment string) string {
	t.Helper()
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
	if comment != "" {
		line += " " + comment
	}
	return line
}

func TestParseKeys(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ed := authorizedKey(t, pub, "alice@laptop")
	keys, err := parseKeys("\n# comment\n" + ed + "\n\n" + authorizedKey(t, pub, "") + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].name != "alice@laptop" || keys[1].name != "ssh-ed25519" {
		t.Fatalf("keys = %+v", keys)
	}
	if _, err := parseKeys("not a key"); err == nil {
		t.Error("garbage accepted")
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseKeys(authorizedKey(t, &weak.PublicKey, "")); err == nil || !strings.Contains(err.Error(), "2048") {
		t.Errorf("weak RSA key: %v", err)
	}
}
