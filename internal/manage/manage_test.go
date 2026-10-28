package manage

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

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
	keys, err := ParseKeys("\n# comment\n" + ed + "\n\n" + authorizedKey(t, pub, "") + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].Name != "alice@laptop" || keys[1].Name != "ssh-ed25519" {
		t.Fatalf("keys = %+v", keys)
	}
	if _, err := ParseKeys("not a key"); err == nil {
		t.Error("garbage accepted")
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseKeys(authorizedKey(t, &weak.PublicKey, "")); err == nil || !strings.Contains(err.Error(), "2048") {
		t.Errorf("weak RSA key: %v", err)
	}
}
