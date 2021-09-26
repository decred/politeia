// Copyright (c) 2018-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"bytes"
	"net/url"
	"text/template"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/google/uuid"
)

const (
	// GUI routes. These are used in notification emails to direct the
	// user to the correct GUI pages.
	guiRouteRegisterNewUser = "/register"
)

// emailUserEmailVerify sends a new user verification email to the provided
// email address. This function is not rate limited by the smtp client because
// the user is only created/updated when this function is successfully executed
// and an email with the verification token is sent to the user. This email is
// also already limited by the verification token expiry hours policy.
func (p *LegacyPoliteiawww) emailUserEmailVerify(email, token, username string) error {
	link, err := p.createEmailLink(www.RouteVerifyNewUser, email,
		token, username)
	if err != nil {
		return err
	}

	tplData := userEmailVerify{
		Username: username,
		Link:     link,
	}

	subject := "Verify Your Email"
	body, err := createBody(userEmailVerifyTmpl, tplData)
	if err != nil {
		return err
	}

	return p.mail.SendTo(subject, body, []string{email})
}

// emailUserKeyUpdate emails the link with the verification token used for
// setting a new key pair if the email server is set up.
func (p *LegacyPoliteiawww) emailUserKeyUpdate(username, publicKey, token string, recipient map[uuid.UUID]string) error {
	link, err := p.createEmailLink(www.RouteVerifyUpdateUserKey, "", token, "")
	if err != nil {
		return err
	}

	tplData := userKeyUpdate{
		PublicKey: publicKey,
		Username:  username,
		Link:      link,
	}

	subject := "Verify Your New Identity"
	body, err := createBody(userKeyUpdateTmpl, tplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, recipient)
}

// emailUserPasswordReset emails the link with the reset password verification
// token to the provided email address.
func (p *LegacyPoliteiawww) emailUserPasswordReset(username, token string, recipient map[uuid.UUID]string) error {
	// Setup URL
	u, err := url.Parse(p.cfg.WebServerAddress + www.RouteResetPassword)
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("verificationtoken", token)
	q.Set("username", username)
	u.RawQuery = q.Encode()

	// Setup email
	subject := "Reset Your Password"
	tplData := userPasswordReset{
		Link: u.String(),
	}
	body, err := createBody(userPasswordResetTmpl, tplData)
	if err != nil {
		return err
	}

	// Send email
	return p.mail.SendToUsers(subject, body, recipient)
}

// emailUserAccountLocked notifies the user its account has been locked and
// emails the link with the reset password verification token if the email
// server is set up.
func (p *LegacyPoliteiawww) emailUserAccountLocked(username string, recipient map[uuid.UUID]string) error {
	var email string
	for _, e := range recipient {
		email = e
	}
	link, err := p.createEmailLink(ResetPasswordGuiRoute,
		email, "", "")
	if err != nil {
		return err
	}

	tplData := userAccountLocked{
		Link:     link,
		Username: username,
	}

	subject := "Locked Account - Reset Your Password"
	body, err := createBody(userAccountLockedTmpl, tplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, recipient)
}

// emailUserPasswordChanged notifies the user that his password was changed,
// and verifies if he was the author of this action, for security purposes.
func (p *LegacyPoliteiawww) emailUserPasswordChanged(username string, recipient map[uuid.UUID]string) error {
	tplData := userPasswordChanged{
		Username: username,
	}

	subject := "Password Changed - Security Notification"
	body, err := createBody(userPasswordChangedTmpl, tplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, recipient)
}

func (p *LegacyPoliteiawww) createEmailLink(path, email, token, username string) (string, error) {
	l, err := url.Parse(p.cfg.WebServerAddress + path)
	if err != nil {
		return "", err
	}

	q := l.Query()
	if email != "" {
		q.Set("email", email)
	}
	if token != "" {
		q.Set("verificationtoken", token)
	}
	if username != "" {
		q.Set("username", username)
	}
	l.RawQuery = q.Encode()

	return l.String(), nil
}

func createBody(tpl *template.Template, tplData interface{}) (string, error) {
	var buf bytes.Buffer
	err := tpl.Execute(&buf, tplData)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}
