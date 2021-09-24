// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"text/template"
)

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

// CMS events

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

const dccSupportOpposeText = `
A DCC has received new support or opposition.

{{.Link}}

Regards,
Contractor Management System
`

var dccSupportOpposeTmpl = template.Must(
	template.New("dccSupportOppose").Parse(dccSupportOpposeText))

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

// Invoice new comment - Send to invoice owner
const invoiceNewCommentText = `
An administrator has submitted a new comment to your invoice, please login to cms.decred.org to view the message.
`

var invoiceNewCommentTmpl = template.Must(
	template.New("invoiceNewComment").Parse(invoiceNewCommentText))
