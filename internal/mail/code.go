package mail

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"net/url"
	"strings"
	"time"
)

//go:embed code.html
var codeHTML string

var codeTemplate = template.Must(template.New("code").Parse(codeHTML))

// Code is an email that carries a one-time code: for signing in, finishing
// the setup, or confirming a new SMTP relay.
//
// Mail apps offer to copy such codes (Gmail's "Copy code", iOS and macOS
// AutoFill) when they find them: the code leads the subject, comes right
// after the first sentence of the text, and stands alone in the HTML,
// digits only, never split by spaces or markup.
type Code struct {
	To   string
	Code string
	// Subject follows the code: "123456 is your intergate sign-in code".
	Subject string
	Heading string
	Intro   string
	// Details are label and value rows under the code, like the settings
	// a code confirms.
	Details [][2]string
	TTL     time.Duration
	// Note says what to do with an email nobody asked for.
	Note string
	// Site is the dashboard's URL, in the footer.
	Site string
}

// Message renders c as plain text and HTML.
func (c Code) Message() Message {
	minutes := int(c.TTL.Round(time.Minute).Minutes())
	host := c.Site
	if u, err := url.Parse(c.Site); err == nil && u.Host != "" {
		host = u.Host
	}
	subject := c.Code + " " + c.Subject

	var text strings.Builder
	fmt.Fprintf(&text, "%s\n\n%s\n\n    %s\n\nIt expires in %d minutes and works once.\n", c.Heading, c.Intro, c.Code, minutes)
	if len(c.Details) > 0 {
		text.WriteString("\n")
		width := 0
		for _, d := range c.Details {
			width = max(width, len(d[0]))
		}
		for _, d := range c.Details {
			fmt.Fprintf(&text, "  %-*s  %s\n", width+1, d[0]+":", d[1])
		}
	}
	fmt.Fprintf(&text, "\n%s\n\n-- \nintergate at %s\n", c.Note, c.Site)

	var html bytes.Buffer
	err := codeTemplate.Execute(&html, map[string]any{
		"Title":     subject,
		"Preheader": fmt.Sprintf("%s is your code. It expires in %d minutes.", c.Code, minutes),
		"Heading":   c.Heading,
		"Intro":     c.Intro,
		"Code":      c.Code,
		"Minutes":   minutes,
		"Details":   c.Details,
		"Note":      c.Note,
		"Site":      c.Site,
		"Host":      host,
	})
	if err != nil {
		panic(err) // a fixed template with plain strings
	}
	return Message{To: c.To, Subject: subject, Body: text.String(), HTML: html.String()}
}
