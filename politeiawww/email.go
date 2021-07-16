// Copyright (c) 2018-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"net/url"
	"strings"
	"text/template"
	"time"

	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/google/uuid"
)

const (
	// GUI routes. These are used in notification emails to direct the
	// user to the correct GUI pages.
	guiRouteRegisterNewUser = "/register"
	guiRouteDCCDetails      = "/dcc/{token}"
)

func createBody(tpl *template.Template, tplData interface{}) (string, error) {
	var buf bytes.Buffer
	err := tpl.Execute(&buf, tplData)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (p *politeiawww) createEmailLink(path, email, token, username string) (string, error) {
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

// emailUserEmailVerify sends a new user verification email to the provided
// email address. This function is not rate limited by the smtp client because
// the user is only created/updated when this function is successfully executed
// and an email with the verification token is sent to the user. This email is
// also already limited by the verification token expiry hours policy.
func (p *politeiawww) emailUserEmailVerify(email, token, username string) error {
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
func (p *politeiawww) emailUserKeyUpdate(username, publicKey, token string, recipient map[uuid.UUID]string) error {
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
func (p *politeiawww) emailUserPasswordReset(username, token string, recipient map[uuid.UUID]string) error {
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
func (p *politeiawww) emailUserAccountLocked(username string, recipient map[uuid.UUID]string) error {
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
func (p *politeiawww) emailUserPasswordChanged(username string, recipient map[uuid.UUID]string) error {
	tplData := userPasswordChanged{
		Username: username,
	}

	subject := "Password Changed - Security Verification"
	body, err := createBody(userPasswordChangedTmpl, tplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, recipient)
}

// emailUserCMSInvite emails the invitation link for the Contractor Management
// System to the provided user email address. This function is not rate limited
// by the smtp client because it is only sent by cms admins.
func (p *politeiawww) emailUserCMSInvite(email, token string) error {
	link, err := p.createEmailLink(guiRouteRegisterNewUser, "", token, "")
	if err != nil {
		return err
	}
	tplData := userCMSInvite{
		Email: email,
		Link:  link,
	}

	subject := "Welcome to the Contractor Management System"
	body, err := createBody(userCMSInviteTmpl, tplData)
	if err != nil {
		return err
	}

	return p.mail.SendTo(subject, body, []string{email})
}

// emailUserDCCApproved emails the link to invite a user that has been approved
// by the other contractors from a DCC proposal.
func (p *politeiawww) emailUserDCCApproved(recipient map[uuid.UUID]string) error {
	var email string
	for _, e := range recipient {
		email = e
	}
	tplData := userDCCApproved{
		Email: email,
	}

	subject := "Congratulations, You've been approved!"
	body, err := createBody(userDCCApprovedTmpl, tplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, recipient)
}

// emailDCCSubmitted sends email regarding the DCC New event. Sends email
// to the provided email addresses.
func (p *politeiawww) emailDCCSubmitted(token string, recipients map[uuid.UUID]string) error {
	route := strings.Replace(guiRouteDCCDetails, "{token}", token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	tplData := dccSubmitted{
		Link: l.String(),
	}

	subject := "New DCC Submitted"
	body, err := createBody(dccSubmittedTmpl, tplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, recipients)
}

// emailDCCSupportOppose sends emails regarding dcc support/oppose event.
// Sends emails to the provided email addresses.
func (p *politeiawww) emailDCCSupportOppose(token string, recipients map[uuid.UUID]string) error {
	route := strings.Replace(guiRouteDCCDetails, "{token}", token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	tplData := dccSupportOppose{
		Link: l.String(),
	}

	subject := "New DCC Support/Opposition Submitted"
	body, err := createBody(dccSupportOpposeTmpl, tplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, recipients)
}

// emailInvoiceStatusUpdate sends email for the invoice status update event.
// Send email for the provided user email address.
func (p *politeiawww) emailInvoiceStatusUpdate(invoiceToken string, recipient map[uuid.UUID]string) error {
	tplData := invoiceStatusUpdate{
		Token: invoiceToken,
	}

	subject := "Invoice status has been updated"
	body, err := createBody(invoiceStatusUpdateTmpl, tplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, recipient)
}

// emailInvoiceNotifications emails users that have not yet submitted an
// invoice for the given month/year
func (p *politeiawww) emailInvoiceNotifications(username, subject string, recipient map[uuid.UUID]string, tmpl *template.Template) error {
	// Set the date to the first day of the previous month.
	newDate := time.Date(time.Now().Year(), time.Now().Month()-1, 1, 0, 0, 0, 0, time.UTC)
	tplData := invoiceNotification{
		Username: username,
		Month:    newDate.Month().String(),
		Year:     newDate.Year(),
	}
	body, err := createBody(tmpl, &tplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, recipient)
}

// emailInvoiceNewComment sends email for the invoice new comment event. Send
// email to the provided user email address.
func (p *politeiawww) emailInvoiceNewComment(recipient map[uuid.UUID]string) error {
	var tplData interface{}
	subject := "New Invoice Comment"

	body, err := createBody(invoiceNewCommentTmpl, tplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, recipient)
}
