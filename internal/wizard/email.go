package wizard

import (
	"strings"

	"github.com/charmbracelet/huh"

	"github.com/jgermade/intergate/internal/admin"
)

// setupLink prints a new link to the dashboard's setup.
func (w *Wizard) setupLink(c *admin.Client) error {
	link, err := c.SetupURL(w.ctx)
	if err != nil {
		return err
	}
	w.printf("\nOpen this link to set up email delivery and the owner. It works once, and replaces\nany link given before:\n\n  %s\n\n", link)
	return nil
}

// passwordSource describes where the SMTP password comes from.
func passwordSource(p string) string {
	switch {
	case p == "stored":
		return "stored in intergate's database, encrypted"
	case strings.HasPrefix(p, "env:"):
		return "the environment variable " + strings.TrimPrefix(p, "env:")
	case strings.HasPrefix(p, "file:"):
		return "the file " + strings.TrimPrefix(p, "file:")
	}
	return "none: the SMTP server needs no sign-in"
}

// email changes where the SMTP password of email delivery set up in the
// dashboard comes from: stored by intergate, or read from an environment
// variable or a file, which a secrets manager (Vault, Kubernetes, Docker)
// can provide.
func (w *Wizard) email(c *admin.Client) error {
	e, err := c.Email(w.ctx)
	if err != nil {
		return err
	}
	user := ""
	if e.Username != "" {
		user = ", user " + e.Username
	}
	w.printf("\nEmail delivery, set up in the dashboard: %s port %d (%s%s), from %s.\nSMTP password: %s.\n\n",
		e.Host, e.Port, e.TLS, user, e.From, passwordSource(e.Password))
	var choice string
	err = w.form(huh.NewGroup(huh.NewSelect[string]().
		Title("Where does the SMTP password come from?").
		Description("intergate checks the password with the SMTP server before changing anything.").
		Options(
			huh.NewOption("Stored by intergate, encrypted (enter it)", "stored"),
			huh.NewOption("An environment variable of the server", "env"),
			huh.NewOption("A file: a Docker or Kubernetes secret, Vault Agent…", "file"),
			huh.NewOption("← Back", "back"),
		).Value(&choice)))
	if err != nil || choice == "back" {
		return err
	}
	var req admin.PasswordRequest
	switch choice {
	case "stored":
		echo := map[bool]huh.EchoMode{true: huh.EchoModePassword, false: huh.EchoModeNormal}[w.passwordInput()]
		err = w.form(huh.NewGroup(huh.NewInput().Title("SMTP password").EchoMode(echo).
			Value(&req.Password).Validate(required("the password"))))
	case "env":
		name := "SMTP_PASSWORD"
		err = w.form(huh.NewGroup(huh.NewInput().Title("Environment variable").
			Description("Set in intergate's environment: /etc/intergate/intergate.env for the service,\n" +
				"-e or --env-file with Docker, secretEnv or existingSecret with Helm.").
			Value(&name).Validate(required("the variable name"))))
		req.Ref = "env:" + strings.TrimSpace(name)
	case "file":
		var path string
		err = w.form(huh.NewGroup(huh.NewInput().Title("File").
			Description("An absolute path the server can read, e.g. /run/secrets/smtp_password.\n" +
				"It is read for every email, so a renewed secret takes effect at once.").
			Value(&path).Validate(required("the path"))))
		req.Ref = "file:" + strings.TrimSpace(path)
	}
	if err != nil {
		return err
	}
	e, err = c.SetEmailPassword(w.ctx, req)
	if err != nil {
		return err
	}
	w.printf("✔ The SMTP password is now %s.\n", passwordSource(e.Password))
	return nil
}
