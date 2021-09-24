// Copyright (c) 2018-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"bytes"
	"net/url"
	"strings"
	"text/template"
	"time"
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

// emailUserCMSInvite emails the invitation link for the Contractor Management
// System to the provided user email address.
func (p *LegacyPoliteiawww) emailUserCMSInvite(email, token string) error {
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
	recipients := []string{email}

	return p.mail.SendTo(subject, body, recipients)
}

// emailUserDCCApproved emails the link to invite a user that has been approved
// by the other contractors from a DCC proposal.
func (p *LegacyPoliteiawww) emailUserDCCApproved(email string) error {
	tplData := userDCCApproved{
		Email: email,
	}

	subject := "Congratulations, You've been approved!"
	body, err := createBody(userDCCApprovedTmpl, tplData)
	if err != nil {
		return err
	}
	recipients := []string{email}

	return p.mail.SendTo(subject, body, recipients)
}

// emailDCCSubmitted sends email regarding the DCC New event. Sends email
// to the provided email addresses.
func (p *LegacyPoliteiawww) emailDCCSubmitted(token string, emails []string) error {
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

	return p.mail.SendTo(subject, body, emails)
}

// emailDCCSupportOppose sends emails regarding dcc support/oppose event.
// Sends emails to the provided email addresses.
func (p *LegacyPoliteiawww) emailDCCSupportOppose(token string, emails []string) error {
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

	return p.mail.SendTo(subject, body, emails)
}

// emailInvoiceStatusUpdate sends email for the invoice status update event.
// Send email for the provided user email address.
func (p *LegacyPoliteiawww) emailInvoiceStatusUpdate(invoiceToken, userEmail string) error {
	tplData := invoiceStatusUpdate{
		Token: invoiceToken,
	}

	subject := "Invoice status has been updated"
	body, err := createBody(invoiceStatusUpdateTmpl, tplData)
	if err != nil {
		return err
	}
	recipients := []string{userEmail}

	return p.mail.SendTo(subject, body, recipients)
}

// emailInvoiceNotifications emails users that have not yet submitted an
// invoice for the given month/year
func (p *LegacyPoliteiawww) emailInvoiceNotifications(email, username, subject string, tmpl *template.Template) error {
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
	recipients := []string{email}

	return p.mail.SendTo(subject, body, recipients)
}

// emailInvoiceNewComment sends email for the invoice new comment event. Send
// email to the provided user email address.
func (p *LegacyPoliteiawww) emailInvoiceNewComment(userEmail string) error {
	var tplData interface{}
	subject := "New Invoice Comment"

	body, err := createBody(invoiceNewCommentTmpl, tplData)
	if err != nil {
		return err
	}
	recipients := []string{userEmail}

	return p.mail.SendTo(subject, body, recipients)
}
