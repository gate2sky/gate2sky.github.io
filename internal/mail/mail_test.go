package mail

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	stdmail "net/mail"
	"strconv"
	"strings"
	"testing"

	"github.com/jgermade/securegate/internal/config"
)

// fakeSMTP accepts one message and records the conversation.
type fakeSMTP struct {
	addr     string
	auth     chan string
	envelope chan [2]string
	data     chan string
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeSMTP{addr: ln.Addr().String(), auth: make(chan string, 1), envelope: make(chan [2]string, 1), data: make(chan string, 1)}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		say := func(s string) { io.WriteString(c, s+"\r\n") }
		say("220 fake ESMTP")
		var from string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(cmd, "EHLO"):
				say("250-fake")
				say("250 AUTH PLAIN")
			case strings.HasPrefix(cmd, "AUTH PLAIN "):
				dec, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(cmd, "AUTH PLAIN "))
				f.auth <- string(dec)
				say("235 ok")
			case strings.HasPrefix(cmd, "MAIL FROM:"):
				from = cmd
				say("250 ok")
			case strings.HasPrefix(cmd, "RCPT TO:"):
				f.envelope <- [2]string{from, cmd}
				say("250 ok")
			case cmd == "DATA":
				say("354 go")
				var b strings.Builder
				for {
					l, err := r.ReadString('\n')
					if err != nil || l == ".\r\n" {
						break
					}
					b.WriteString(l)
				}
				f.data <- b.String()
				say("250 queued")
			case cmd == "QUIT":
				say("221 bye")
				return
			default:
				say("250 ok")
			}
		}
	}()
	return f
}

func TestSMTPSender(t *testing.T) {
	f := newFakeSMTP(t)
	host, port, _ := net.SplitHostPort(f.addr)
	p, _ := strconv.Atoi(port)
	s := New(config.EmailConfig{
		From: "securegate <no-reply@gate.example.com>",
		SMTP: config.SMTPConfig{Host: host, Port: p, TLS: "none", Username: "user", Password: "pw"},
	}, nil)
	err := s.Send(context.Background(), Message{To: "alice@example.com", Subject: "Your code: 123456", Body: "Code:\n\n    123456\n"})
	if err != nil {
		t.Fatal(err)
	}
	if got := <-f.auth; got != "\x00user\x00pw" {
		t.Errorf("AUTH PLAIN = %q", got)
	}
	if env := <-f.envelope; env[0] != "MAIL FROM:<no-reply@gate.example.com>" || env[1] != "RCPT TO:<alice@example.com>" {
		t.Errorf("envelope = %q", env)
	}
	msg, err := stdmail.ReadMessage(strings.NewReader(<-f.data))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Header.Get("Subject") != "Your code: 123456" || msg.Header.Get("To") != "<alice@example.com>" || msg.Header.Get("Message-Id") == "" {
		t.Errorf("headers = %v", msg.Header)
	}
	body, _ := io.ReadAll(msg.Body)
	if !strings.Contains(string(body), "    123456") {
		t.Errorf("body = %q", body)
	}
}
