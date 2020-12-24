// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "text/template"

// Proposal submitted - Send to admins
type proposalSubmitted struct {
	Username string // Author username
	Name     string // Proposal name
	Link     string // GUI proposal details URL
}

const proposalSubmittedText = `
A new proposal has been submitted on Politeia by {{.Username}}:

{{.Name}}
{{.Link}}
`

var proposalSubmittedTmpl = template.Must(
	template.New("proposalSubmitted").Parse(proposalSubmittedText))

// Proposal edited - Send to users
type proposalEdited struct {
	Name     string // Proposal name
	Version  string // ProposalVersion
	Username string // Author username
	Link     string // GUI proposal details URL
}

const proposalEditedText = `
A proposal by {{.Username}} has just been edited:

{{.Name}} (Version: {{.Version}})
{{.Link}}
`

var proposalEditedTmpl = template.Must(
	template.New("proposalEdited").Parse(proposalEditedText))

// Proposal status change - Vetted - Send to users
type proposalVetted struct {
	Name string // Proposal name
	Link string // GUI proposal details URL
}

const proposalVettedText = `
A new proposal has just been published on Politeia.

{{.Name}}
{{.Link}}
`

var tmplProposalVetted = template.Must(
	template.New("proposalVetted").Parse(proposalVettedText))

// Proposal status change - Vetted - Send to author
type proposalVettedToAuthor struct {
	Name string // Proposal name
	Link string // GUI proposal details URL
}

const proposalVettedToAuthorText = `
Your proposal has just been made public on Politeia!  

Your proposal has now entered the discussion phase where the community can
leave comments and provide feedback.  Be sure to keep an eye out for new
comments and to answer any questions that the community may have.  You are
allowed to edit your proposal at any point prior to the start of voting.

Once you feel that enough time has been given for discussion you may authorize
the vote to commence on your proposal.  An admin is not able to start the
voting process until you explicitly authorize it.  You can authorize a proposal
vote by opening the proposal page and clicking on the "Authorize Voting to
Start" button.

{{.Name}}
{{.Link}}

If you have any questions, drop by the proposals channel on matrix.
https://chat.decred.org/#/room/#proposals:decred.org
`

var proposalVettedToAuthorTmpl = template.Must(
	template.New("proposalVettedToAuthor").Parse(proposalVettedToAuthorText))

// Proposal status change - Censored - Send to author
type proposalCensoredToAuthor struct {
	Name   string // Proposal name
	Reason string // Reason for censoring
}

const proposalCensoredToAuthorText = `
Your proposal on Politeia has been censored.

{{.Name}}
Reason: {{.Reason}}
`

var tmplProposalCensoredForAuthor = template.Must(
	template.New("proposalCensoredToAuthor").Parse(proposalCensoredToAuthorText))

// Proposal comment submitted - Send to proposal author
type proposalCommentSubmitted struct {
	Username string // Comment author username
	Name     string // Proposal name
	Link     string // Comment link
}

const proposalCommentSubmittedText = `
{{.Username}} has commented on your proposal!

Proposal: {{.Name}}
Comment: {{.Link}}
`

var proposalCommentSubmittedTmpl = template.Must(
	template.New("proposalCommentSubmitted").Parse(proposalCommentSubmittedText))

// Proposal comment reply - Send to parent comment author
type proposalCommentReply struct {
	Username string // Comment author username
	Name     string // Proposal name
	Link     string // Comment link
}

const proposalCommentReplyText = `
{{.Username}} has replied to your comment!

Proposal: {{.Name}}
Comment: {{.Link}}
`

var proposalCommentReplyTmpl = template.Must(
	template.New("proposalCommentReply").Parse(proposalCommentReplyText))

// Proposal vote authorized - Send to admins
type proposalVoteAuthorized struct {
	Username string // Author username
	Name     string // Proposal name
	Link     string // GUI proposal details url
}

const proposalVoteAuthorizedText = `
{{.Username}} has authorized a vote on their proposal.

{{.Name}}
{{.Link}}
`

var proposalVoteAuthorizedTmpl = template.Must(
	template.New("proposalVoteAuthorized").Parse(proposalVoteAuthorizedText))

// Proposal vote started - Send to users
type proposalVoteStarted struct {
	Name string // Proposal name
	Link string // GUI proposal details url
}

const proposalVoteStartedText = `
Voting has started on a Politeia proposal!

{{.Name}}
{{.Link}}
`

var proposalVoteStartedTmpl = template.Must(
	template.New("proposalVoteStarted").Parse(proposalVoteStartedText))

// Proposal vote started - Send to author
type proposalVoteStartedToAuthor struct {
	Name string // Proposal name
	Link string // GUI proposal details url
}

const proposalVoteStartedToAuthorText = `
Voting has just started on your Politeia proposal!

{{.Name}}
{{.Link}}
`

var proposalVoteStartedToAuthorTmpl = template.Must(
	template.New("proposalVoteStartedToAuthor").
		Parse(proposalVoteStartedToAuthorText))

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

// Invoice not sent - Send to users that did not send monthly invoice yet
type invoiceNotSent struct {
	Username string // User username
	Month    string // Current month
	Year     int    // Current year
}

const invoiceNotSentText = `
{{.Username}},

You have not yet submitted an invoice for {{.Month}} {{.Year}}.  Please do so as soon as possible, so your invoice may be reviewed and paid out in a timely manner.

Regards,
Contractor Management System
`

var invoiceNotSentTmpl = template.Must(
	template.New("invoiceNotSent").Parse(invoiceNotSentText))

// Invoice new comment - Send to invoice owner
const invoiceNewCommentText = `
An administrator has submitted a new comment to your invoice, please login to cms.decred.org to view the message.
`

var invoiceNewCommentTmpl = template.Must(
	template.New("invoiceNewComment").Parse(invoiceNewCommentText))
