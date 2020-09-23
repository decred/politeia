// Copyright (c) 2018-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"text/template"
	"time"

	pi "github.com/decred/politeia/politeiawww/api/pi/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
)

const (
	// GUI routes. These are used in notification emails to direct the
	// user to the correct GUI pages.
	guiRouteProposalDetails  = "/proposals/{token}"
	guirouteProposalComments = "/proposals/{token}/comments/{id}"
	guiRouteRegisterNewUser  = "/register"
	guiRouteDCCDetails       = "/dcc/{token}"
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

// emailProposalSubmitted send a proposal submitted notification email to
// the provided list of emails.
func (p *politeiawww) emailProposalSubmitted(token, name, username string, emails []string) error {
	route := strings.Replace(guiRouteProposalDetails, "{token}", token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	tmplData := proposalSubmitted{
		Username: username,
		Name:     name,
		Link:     l.String(),
	}

	subject := "New Proposal Submitted"
	body, err := createBody(proposalSubmittedTmpl, tmplData)
	if err != nil {
		return err
	}

	return p.smtp.sendEmailTo(subject, body, emails)
}

// emailProposalEdited sends a proposal edited notification email to the
// provided list of emails.
func (p *politeiawww) emailProposalEdited(name, username, token, version string, emails []string) error {
	route := strings.Replace(guiRouteProposalDetails, "{token}", token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	tmplData := proposalEdited{
		Name:     name,
		Version:  version,
		Username: username,
		Link:     l.String(),
	}

	subject := "Proposal Edited"
	body, err := createBody(proposalEditedTmpl, tmplData)
	if err != nil {
		return err
	}

	return p.smtp.sendEmailTo(subject, body, emails)
}

// emailProposalStatusChange sends a proposal status change email to the
// provided email addresses.
func (p *politeiawww) emailProposalStatusChange(d dataProposalStatusChange, proposalName string, emails []string) error {
	route := strings.Replace(guiRouteProposalDetails, "{token}", d.token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	var (
		subject string
		body    string
	)
	switch d.status {
	case pi.PropStatusPublic:
		subject = "New Proposal Published"
		tmplData := proposalVetted{
			Name: proposalName,
			Link: l.String(),
		}
		body, err = createBody(tmplProposalVetted, tmplData)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("no user notification for prop status %v", d.status)
	}

	return p.smtp.sendEmailTo(subject, body, emails)
}

// emailProposalStatusChangeAuthor sends a proposal status change notification
// email to the provided email address.
func (p *politeiawww) emailProposalStatusChangeToAuthor(d dataProposalStatusChange, proposalName, authorEmail string) error {
	route := strings.Replace(guiRouteProposalDetails, "{token}", d.token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	var (
		subject string
		body    string
	)
	switch d.status {
	case pi.PropStatusPublic:
		subject = "Your Proposal Has Been Published"
		tmplData := proposalVettedToAuthor{
			Name: proposalName,
			Link: l.String(),
		}
		body, err = createBody(proposalVettedToAuthorTmpl, tmplData)
		if err != nil {
			return err
		}

	case pi.PropStatusCensored:
		subject = "Your Proposal Has Been Censored"
		tmplData := proposalCensoredToAuthor{
			Name:   proposalName,
			Reason: d.reason,
		}
		body, err = createBody(tmplProposalCensoredForAuthor, tmplData)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("no author notification for prop status %v", d.status)
	}

	return p.smtp.sendEmailTo(subject, body, []string{authorEmail})
}

// emailProposalCommentSubmitted sends a proposal comment submitted email to
// the provided email address.
func (p *politeiawww) emailProposalCommentSubmitted(token, commentID, commentUsername, proposalName, proposalAuthorEmail string) error {
	// Setup comment URL
	route := strings.Replace(guirouteProposalComments, "{token}", token, 1)
	route = strings.Replace(route, "{id}", commentID, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	// Setup email
	subject := "New Comment On Your Proposal"
	tmplData := proposalCommentSubmitted{
		Username: commentUsername,
		Name:     proposalName,
		Link:     l.String(),
	}
	body, err := createBody(proposalCommentSubmittedTmpl, tmplData)
	if err != nil {
		return err
	}

	// Send email
	return p.smtp.sendEmailTo(subject, body, []string{proposalAuthorEmail})
}

// emailProposalCommentReply sends a proposal comment reply email to the
// provided email address.
func (p *politeiawww) emailProposalCommentReply(token, commentID, commentUsername, proposalName, parentCommentEmail string) error {
	// Setup comment URL
	route := strings.Replace(guirouteProposalComments, "{token}", token, 1)
	route = strings.Replace(route, "{id}", commentID, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	// Setup email
	subject := "New Reply To Your Comment"
	tmplData := proposalCommentReply{
		Username: commentUsername,
		Name:     proposalName,
		Link:     l.String(),
	}
	body, err := createBody(proposalCommentReplyTmpl, tmplData)
	if err != nil {
		return err
	}

	// Send email
	return p.smtp.sendEmailTo(subject, body, []string{parentCommentEmail})
}

// emailProposalVoteAuthorized sends a proposal vote authorized email to the
// provided list of emails.
func (p *politeiawww) emailProposalVoteAuthorized(token, name, username string, emails []string) error {
	// Setup URL
	route := strings.Replace(guiRouteProposalDetails, "{token}", token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	// Setup email
	subject := "Proposal Authorized To Start Voting"
	tplData := proposalVoteAuthorized{
		Username: username,
		Name:     name,
		Link:     l.String(),
	}
	body, err := createBody(proposalVoteAuthorizedTmpl, tplData)
	if err != nil {
		return err
	}

	// Send email
	return p.smtp.sendEmailTo(subject, body, emails)
}

// emailProposalVoteStarted sends a proposal vote started email notification
// to the provided email addresses.
func (p *politeiawww) emailProposalVoteStarted(token, name string, emails []string) error {
	// Setup URL
	route := strings.Replace(guiRouteProposalDetails, "{token}", token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	// Setup email
	subject := "Voting Started for Proposal"
	tplData := proposalVoteStarted{
		Name: name,
		Link: l.String(),
	}
	body, err := createBody(proposalVoteStartedTmpl, tplData)
	if err != nil {
		return err
	}

	// Send email
	return p.smtp.sendEmailTo(subject, body, emails)
}

// emailProposalVoteStartedToAuthor sends a proposal vote started email to
// the provided email address.
func (p *politeiawww) emailProposalVoteStartedToAuthor(token, name, username, email string) error {
	// Setup URL
	route := strings.Replace(guiRouteProposalDetails, "{token}", token, 1)
	l, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	// Setup email
	subject := "Your Proposal Has Started Voting"
	tplData := proposalVoteStartedToAuthor{
		Name: name,
		Link: l.String(),
	}
	body, err := createBody(proposalVoteStartedToAuthorTmpl, tplData)
	if err != nil {
		return err
	}

	// Send email
	return p.smtp.sendEmailTo(subject, body, []string{email})
}

// emailUserEmailVerify sends a new user verification email to the
// provided email address.
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
	recipients := []string{email}

	return p.smtp.sendEmailTo(subject, body, recipients)
}

// emailUserKeyUpdate emails the link with the verification token used for
// setting a new key pair if the email server is set up.
func (p *politeiawww) emailUserKeyUpdate(username, email, publicKey, token string) error {
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
	recipients := []string{email}

	return p.smtp.sendEmailTo(subject, body, recipients)
}

// emailUserPasswordReset emails the link with the reset password verification
// token to the provided email address.
func (p *politeiawww) emailUserPasswordReset(email, username, token string) error {
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
	return p.smtp.sendEmailTo(subject, body, []string{email})
}

// emailUserAccountLocked notifies the user its account has been locked and
// emails the link with the reset password verification token if the email
// server is set up.
func (p *politeiawww) emailUserAccountLocked(username, email string) error {
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
	recipients := []string{email}

	return p.smtp.sendEmailTo(subject, body, recipients)
}

// emailUserPasswordChanged notifies the user that his password was changed,
// and verifies if he was the author of this action, for security purposes.
func (p *politeiawww) emailUserPasswordChanged(username, email string) error {
	tplData := userPasswordChanged{
		Username: username,
	}

	subject := "Password Changed - Security Verification"
	body, err := createBody(userPasswordChangedTmpl, tplData)
	if err != nil {
		return err
	}
	recipients := []string{email}

	return p.smtp.sendEmailTo(subject, body, recipients)
}

// emailUserCMSInvite emails the invitation link for the Contractor Management
// System to the provided user email address.
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
	recipients := []string{email}

	return p.smtp.sendEmailTo(subject, body, recipients)
}

// emailUserDCCApproved emails the link to invite a user that has been approved
// by the other contractors from a DCC proposal.
func (p *politeiawww) emailUserDCCApproved(email string) error {
	tplData := userDCCApproved{
		Email: email,
	}

	subject := "Congratulations, You've been approved!"
	body, err := createBody(userDCCApprovedTmpl, tplData)
	if err != nil {
		return err
	}
	recipients := []string{email}

	return p.smtp.sendEmailTo(subject, body, recipients)
}

// emailDCCSubmitted sends email regarding the DCC New event. Sends email
// to the provided email addresses.
func (p *politeiawww) emailDCCSubmitted(token string, emails []string) error {
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

	return p.smtp.sendEmailTo(subject, body, emails)
}

// emailDCCSupportOppose sends emails regarding dcc support/oppose event.
// Sends emails to the provided email addresses.
func (p *politeiawww) emailDCCSupportOppose(token string, emails []string) error {
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

	return p.smtp.sendEmailTo(subject, body, emails)
}

// emailInvoiceStatusUpdate sends email for the invoice status update event.
// Send email for the provided user email address.
func (p *politeiawww) emailInvoiceStatusUpdate(invoiceToken, userEmail string) error {
	tplData := invoiceStatusUpdate{
		Token: invoiceToken,
	}

	subject := "Invoice status has been updated"
	body, err := createBody(invoiceStatusUpdateTmpl, tplData)
	if err != nil {
		return err
	}
	recipients := []string{userEmail}

	return p.smtp.sendEmailTo(subject, body, recipients)
}

// emailInvoiceNotSent sends a invoice not sent email notification to the
// provided email address.
func (p *politeiawww) emailInvoiceNotSent(email, username string) error {
	// Set the date to the first day of the previous month.
	newDate := time.Date(time.Now().Year(), time.Now().Month()-1, 1, 0, 0, 0, 0, time.UTC)
	tplData := invoiceNotSent{
		Username: username,
		Month:    newDate.Month().String(),
		Year:     newDate.Year(),
	}

	subject := "Awaiting Monthly Invoice"
	body, err := createBody(invoiceNotSentTmpl, tplData)
	if err != nil {
		return err
	}
	recipients := []string{email}

	return p.smtp.sendEmailTo(subject, body, recipients)
}

// emailInvoiceNewComment sends email for the invoice new comment event. Send
// email to the provided user email address.
func (p *politeiawww) emailInvoiceNewComment(userEmail string) error {
	var tplData interface{}
	subject := "New Invoice Comment"

	body, err := createBody(invoiceNewCommentTmpl, tplData)
	if err != nil {
		return err
	}
	recipients := []string{userEmail}

	return p.smtp.sendEmailTo(subject, body, recipients)
}
