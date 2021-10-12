// Copyright (c) 2017-2020 The Decred developers
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
func (p *Politeiawww) emailUserEmailVerify(email, token, username string) error {
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
func (p *Politeiawww) emailUserKeyUpdate(username, publicKey, token string, recipient map[uuid.UUID]string) error {
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
func (p *Politeiawww) emailUserPasswordReset(username, token string, recipient map[uuid.UUID]string) error {
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
func (p *Politeiawww) emailUserAccountLocked(username string, recipient map[uuid.UUID]string) error {
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
func (p *Politeiawww) emailUserPasswordChanged(username string, recipient map[uuid.UUID]string) error {
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

func (p *Politeiawww) createEmailLink(path, email, token, username string) (string, error) {
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

// User email verify - Send verification link to new user
type userEmailVerify struct {
	Username string // User username
	Link     string // Verification link
}

const userEmailVerifyText = `
Thanks for joining Politeia, {{.Username}}!

Click the link below to verify your email and complete your registration.

{{.Link}}

You are receiving this notification because this email address was used to
register a Politeia account.  If you did not perform this action, please ignore
this email.
`

var userEmailVerifyTmpl = template.Must(
	template.New("userEmailVerify").Parse(userEmailVerifyText))

// User key update - Send key verification link to user
type userKeyUpdate struct {
	PublicKey string // User new public key
	Username  string
	Link      string // Verify key link
}

const userKeyUpdateText = `
Click the link below to verify your new identity:

{{.Link}}

You are receiving this notification because a new identity was generated for
{{.Username}} on Politeia with the following public key. 

Public key: {{.PublicKey}} 

If you did not perform this action, please contact a Politeia administrators in
the Politeia channel on Matrix.

https://chat.decred.org/#/room/#politeia:decred.org
`

var userKeyUpdateTmpl = template.Must(
	template.New("userKeyUpdate").Parse(userKeyUpdateText))

// User password reset - Send password reset link to user
type userPasswordReset struct {
	Link string // Password reset link
}

const userPasswordResetText = `
Click the link below to continue resetting your password:

{{.Link}}

A password reset was initiated for this Politeia account.  If you did not
perform this action, it's possible that your account has been compromised.
Please contact a Politeia administrator in the Politeia channel on Matrix.

https://chat.decred.org/#/room/#politeia:decred.org
`

var userPasswordResetTmpl = template.Must(
	template.New("userPasswordReset").Parse(userPasswordResetText))

// User account locked - Send reset password link to user
type userAccountLocked struct {
	Link     string // Reset password link
	Username string
}

const userAccountLockedText = `
The Politeia account for {{.Username}} was locked due to too many login
attempts. You need to reset your password in order to unlock your account:

{{.Link}}

If these login attempts were not made by you, please notify a Politeia
administrators in the Politeia channel on Matrix.

https://chat.decred.org/#/room/#politeia:decred.org
`

var userAccountLockedTmpl = template.Must(
	template.New("userAccountLocked").Parse(userAccountLockedText))

// User password changed - Send to user
type userPasswordChanged struct {
	Username string
}

const userPasswordChangedText = `
The password has been changed for your Politeia account with the username
{{.Username}}. 

If you did not perform this action, it's possible that your account has been
compromised.  Please contact a Politeia administrator in the Politeia channel
on Matrix.

https://chat.decred.org/#/room/#politeia:decred.org
`

var userPasswordChangedTmpl = template.Must(
	template.New("userPasswordChanged").Parse(userPasswordChangedText))
