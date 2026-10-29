// Package mail sends the sign-in emails.
package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/jgermade/intergate/internal/config"
)

// Message is a plain-text email.
type Message struct {
	To      string
	Subject string
	Body    string
}

// Sender delivers messages.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// New returns the sender configured in cfg.
func New(cfg config.EmailConfig, log *slog.Logger) Sender {
	if cfg.LogOnly {
		return &LogSender{log: log}
	}
	return &SMTPSender{cfg: cfg}
}

// LogSender writes messages to the log. For local development only.
type LogSender struct{ log *slog.Logger }

func (l *LogSender) Send(_ context.Context, m Message) error {
	l.log.Warn("email not sent (auth.email.log_only)", "to", m.To, "subject", m.Subject, "body", m.Body)
	return nil
}

// SMTPSender delivers messages through an SMTP server.
type SMTPSender struct {
	cfg config.EmailConfig
}

func (s *SMTPSender) Send(ctx context.Context, m Message) error {
	from, err := mail.ParseAddress(s.cfg.From)
	if err != nil {
		return err
	}
	to, err := mail.ParseAddress(m.To)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c, err := dial(ctx, s.cfg.SMTP)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Mail(from.Address); err != nil {
		return fmt.Errorf("smtp: MAIL FROM: %w", err)
	}
	if err := c.Rcpt(to.Address); err != nil {
		return fmt.Errorf("smtp: RCPT TO: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp: DATA: %w", err)
	}
	if _, err := w.Write(Compose(from, to, m.Subject, m.Body)); err != nil {
		return fmt.Errorf("smtp: write message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: send message: %w", err)
	}
	return c.Quit()
}

// Check connects to the SMTP server of cfg and signs in, without sending
// anything: it tells whether the server, its encryption and the
// credentials are right.
func Check(ctx context.Context, cfg config.SMTPConfig) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	c, err := dial(ctx, cfg)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.Quit()
}

// dial connects to the SMTP server, encrypts the connection as configured
// and signs in.
func dial(ctx context.Context, smtpCfg config.SMTPConfig) (*smtp.Client, error) {
	addr := net.JoinHostPort(smtpCfg.Host, strconv.Itoa(smtpCfg.Port))
	tlsCfg := &tls.Config{ServerName: smtpCfg.Host, MinVersion: tls.VersionTLS12}
	var conn net.Conn
	var err error
	if smtpCfg.TLS == "tls" {
		conn, err = (&tls.Dialer{Config: tlsCfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("smtp: connect to %s: %w", addr, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	c, err := smtp.NewClient(conn, smtpCfg.Host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("smtp: %w", err)
	}
	if smtpCfg.TLS == "starttls" {
		if err := c.StartTLS(tlsCfg); err != nil {
			c.Close()
			return nil, fmt.Errorf("smtp: STARTTLS: %w", err)
		}
	}
	if smtpCfg.Username != "" {
		// PlainAuth refuses to send credentials without TLS (except to
		// localhost).
		if err := c.Auth(smtp.PlainAuth("", smtpCfg.Username, smtpCfg.Password, smtpCfg.Host)); err != nil {
			c.Close()
			return nil, fmt.Errorf("smtp: authenticate: %w", err)
		}
	}
	return c, nil
}

// Compose renders an RFC 5322 message with a quoted-printable UTF-8 body.
func Compose(from, to *mail.Address, subject, body string) []byte {
	id := make([]byte, 12)
	rand.Read(id)
	domain := from.Address[strings.LastIndexByte(from.Address, '@')+1:]

	var b bytes.Buffer
	header := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	header("From", from.String())
	header("To", to.String())
	header("Subject", mime.QEncoding.Encode("utf-8", subject))
	header("Date", time.Now().Format(time.RFC1123Z))
	header("Message-ID", "<"+hex.EncodeToString(id)+"@"+domain+">")
	header("MIME-Version", "1.0")
	header("Content-Type", "text/plain; charset=utf-8")
	header("Content-Transfer-Encoding", "quoted-printable")
	header("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	qp.Write([]byte(strings.ReplaceAll(body, "\n", "\r\n")))
	qp.Close()
	return b.Bytes()
}
