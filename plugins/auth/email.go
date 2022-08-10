// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package auth

import (
	"bytes"
	"html/template"
	"strings"

	"github.com/dajohi/goemail"
)

func (p *authp) sendEmail(subject, body string, recipients []string) error {
	if p.smtp == nil {
		log.Debugf("Email is disabled; skipping send email")
		return nil
	}
	msg := goemail.NewMessage(p.emailAddress, subject, body)
	msg.SetName(p.emailName)
	for _, v := range recipients {
		msg.AddBCC(v)
	}
	return p.smtp.Send(msg)
}

func (p *authp) sendEmailVerification(username, email, token string) error {
	t, err := template.New("verify_email").Parse(verifyEmailText)
	if err != nil {
		return err
	}
	data := struct {
		Username string
		Link     string
	}{
		Username: username,
		Link:     p.contactVerificationLink(username, token),
	}
	body, err := templateString(t, data)
	if err != nil {
		return err
	}
	subject := "Verify Your Email"
	return p.sendEmail(subject, body, []string{email})
}

const verifyEmailText = `
Thanks for joining Politeia, {{.Username}}!

Click the link below to verify your email address.

{{.Link}}

You are receiving this notification because this email address was used to
register a Politeia account. If you did not perform this action, please ignore
this email.
`

func (p *authp) contactVerificationLink(username, token string) string {
	host := strings.TrimRight(p.settings.Host.String(), "/")

	link := host + "/user/{username}/verifycontact/{token}"
	link = strings.Replace(link, "{username}", username, 1)
	link = strings.Replace(link, "{token}", token, 1)

	return link
}

func templateString(t *template.Template, templateData interface{}) (string, error) {
	var b bytes.Buffer
	err := t.Execute(&b, templateData)
	if err != nil {
		return "", err
	}
	return b.String(), nil
}
