// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cms

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
	guiRouteDCCDetails      = "/dcc/{token}"
	guiRouteRegisterNewUser = "/register"
)

// User CMS invite - Send to user being invited
type userCMSInvite struct {
	Email string // User email
	Link  string // Registration link
}

const userCMSInviteText = `
You are invited to join Decred as a contractor! To complete your registration, you will need to use the following link and register on the CMS site:

{{.Link}}

You are receiving this email because {{.Email}} was used to be invited to Decred's Contractor Management System.
If you do not recognize this, please ignore this email.
`

var userCMSInviteTmpl = template.Must(
	template.New("userCMSInvite").Parse(userCMSInviteText))

// mailUserCMSInvite emails the invitation link for the Contractor Management
// System to the provided user email address.
func (c *Cms) mailUserCMSInvite(email, token string) error {
	route := strings.Replace(guiRouteRegisterNewUser, "{token}", token, 1)
	u, err := url.Parse(c.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	tplData := userCMSInvite{
		Email: email,
		Link:  u.String(),
	}

	subject := "Welcome to the Contractor Management System"
	body, err := populateTemplate(userCMSInviteTmpl, tplData)
	if err != nil {
		return err
	}
	recipients := []string{email}

	return c.mail.SendTo(subject, body, recipients)
}

// User DCC approved - Send to approved user
type userDCCApproved struct {
	Email string // User email
}

const userDCCApprovedText = `
Congratulations! Your Decred Contractor Clearance Proposal has been approved! 

You are now a fully registered contractor and may now submit invoices.  You should also be receiving an invitation to the contractors room on matrix.  
If you have any questions please feel free to ask them there.

You are receiving this email because {{.Email}} was used to be invited to Decred's Contractor Management System.
If you do not recognize this, please ignore this email.
`

var userDCCApprovedTmpl = template.Must(
	template.New("userDCCApproved").Parse(userDCCApprovedText))

// mailUserDCCApproved emails the link to invite a user that has been approved
// by the other contractors from a DCC proposal.
func (c *Cms) mailUserDCCApproved(email string) error {
	tplData := userDCCApproved{
		Email: email,
	}

	subject := "Congratulations, You've been approved!"
	body, err := populateTemplate(userDCCApprovedTmpl, tplData)
	if err != nil {
		return err
	}
	recipients := []string{email}

	return c.mail.SendTo(subject, body, recipients)
}

// DCC submitted - Send to admins
type dccSubmitted struct {
	Link string // DCC gui link
}

const dccSubmittedText = `
A new DCC has been submitted.

{{.Link}}

Regards,
Contractor Management System
`

var dccSubmittedTmpl = template.Must(
	template.New("dccSubmitted").Parse(dccSubmittedText))

// DCC support/oppose - Send to admins
type dccSupportOppose struct {
	Link string // DCC gui link
}

// mailDCCSubmitted sends email regarding the DCC New event. Sends email
// to the provided email addresses.
func (c *Cms) mailDCCSubmitted(token string, emails []string) error {
	route := strings.Replace(guiRouteDCCDetails, "{token}", token, 1)
	l, err := url.Parse(c.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	tplData := dccSubmitted{
		Link: l.String(),
	}

	subject := "New DCC Submitted"
	body, err := populateTemplate(dccSubmittedTmpl, tplData)
	if err != nil {
		return err
	}

	return c.mail.SendTo(subject, body, emails)
}

const dccSupportOpposeText = `
A DCC has received new support or opposition.

{{.Link}}

Regards,
Contractor Management System
`

var dccSupportOpposeTmpl = template.Must(
	template.New("dccSupportOppose").Parse(dccSupportOpposeText))

// mailDCCSupportOppose sends emails regarding dcc support/oppose event.
// Sends emails to the provided email addresses.
func (c *Cms) mailDCCSupportOppose(token string, emails []string) error {
	route := strings.Replace(guiRouteDCCDetails, "{token}", token, 1)
	l, err := url.Parse(c.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	tplData := dccSupportOppose{
		Link: l.String(),
	}

	subject := "New DCC Support/Opposition Submitted"
	body, err := populateTemplate(dccSupportOpposeTmpl, tplData)
	if err != nil {
		return err
	}

	return c.mail.SendTo(subject, body, emails)
}

// Invoice status update - Send to invoice owner
type invoiceStatusUpdate struct {
	Token string // Invoice token
}

const invoiceStatusUpdateText = `
An invoice's status has been updated, please login to cms.decred.org to review the changes.

Updated Invoice Token: {{.Token}}

Regards,
Contractor Management System
`

var invoiceStatusUpdateTmpl = template.Must(
	template.New("invoiceStatusUpdate").Parse(invoiceStatusUpdateText))

// mailInvoiceStatusUpdate sends email for the invoice status update event.
// Send email for the provided user email address.
func (c *Cms) mailInvoiceStatusUpdate(invoiceToken, userEmail string) error {
	tplData := invoiceStatusUpdate{
		Token: invoiceToken,
	}

	subject := "Invoice status has been updated"
	body, err := populateTemplate(invoiceStatusUpdateTmpl, tplData)
	if err != nil {
		return err
	}
	recipients := []string{userEmail}

	return c.mail.SendTo(subject, body, recipients)
}

// Invoice notifications
var invoiceFirstNotificationTmpl = template.Must(
	template.New("first_invoice_notification").Parse(invoiceFirstText))
var invoiceSecondNotificationTmpl = template.Must(
	template.New("second_invoice_notification").Parse(invoiceSecondText))
var invoiceFinalNotificationTmpl = template.Must(
	template.New("final_invoice_notification").Parse(invoiceFinalText))

type invoiceNotification struct {
	Username string
	Month    string
	Year     int
}

const invoiceFirstText = `
{{.Username}},

Please submit your invoice for {{.Month}} {{.Year}}.

Regards,
Contractor Management System
`

const invoiceSecondText = `
{{.Username}},

You have not yet submitted an invoice for {{.Month}} {{.Year}}.

Regards,
Contractor Management System`

const invoiceFinalText = `
{{.Username}},

You have not yet submitted an invoice for {{.Month}} {{.Year}}.  This is the final warning you will receive, if you delay further, you may not be included in this month's payout.

Regards,
Contractor Management System
`

// mailInvoiceNotifications emails users that have not yet submitted an
// invoice for the given month/year
func (c *Cms) mailInvoiceNotifications(email, username, subject string, tmpl *template.Template) error {
	// Set the date to the first day of the previous month.
	newDate := time.Date(time.Now().Year(), time.Now().Month()-1, 1, 0, 0, 0, 0, time.UTC)
	tplData := invoiceNotification{
		Username: username,
		Month:    newDate.Month().String(),
		Year:     newDate.Year(),
	}
	body, err := populateTemplate(tmpl, &tplData)
	if err != nil {
		return err
	}
	recipients := []string{email}

	return c.mail.SendTo(subject, body, recipients)
}

// Invoice new comment - Send to invoice owner
const invoiceNewCommentText = `
An administrator has submitted a new comment to your invoice, please login to cms.decred.org to view the message.
`

var invoiceNewCommentTmpl = template.Must(
	template.New("invoiceNewComment").Parse(invoiceNewCommentText))

// mailInvoiceNewComment sends email for the invoice new comment event. Send
// email to the provided user email address.
func (c *Cms) mailInvoiceNewComment(userEmail string) error {
	var tplData interface{}
	subject := "New Invoice Comment"

	body, err := populateTemplate(invoiceNewCommentTmpl, tplData)
	if err != nil {
		return err
	}
	recipients := []string{userEmail}

	return c.mail.SendTo(subject, body, recipients)
}

func populateTemplate(tmpl *template.Template, tmplData interface{}) (string, error) {
	var b bytes.Buffer
	err := tmpl.Execute(&b, tmplData)
	if err != nil {
		return "", err
	}
	return b.String(), nil
}
