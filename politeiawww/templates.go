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

// User events
type newUserEmailTemplateData struct {
	Username string
	Link     string
	Email    string
}

const templateNewUserEmailRaw = `
Thanks for joining Politeia, {{.Username}}!

Click the link below to verify your email and complete your registration:

{{.Link}}

You are receiving this email because {{.Email}} was used to register for Politeia.
If you did not perform this action, please ignore this email.
`

type updateUserKeyEmailTemplateData struct {
	Link      string
	PublicKey string
	Email     string
}

const templateUpdateUserKeyEmailRaw = `
Click the link below to verify your new identity:

{{.Link}}

You are receiving this email because a new identity (public key: {{.PublicKey}})
was generated for {{.Email}} on Politeia. If you did not perform this action,
please contact Politeia administrators.
`

type resetPasswordEmailTemplateData struct {
	Link  string
	Email string
}

const templateResetPasswordEmailRaw = `
Click the link below to continue resetting your password:

{{.Link}}

You are receiving this email because a password reset was initiated for {{.Email}}
on Politeia. If you did not perform this action, it is possible that your account has been
compromised. Please contact Politeia administrators through Matrix on the
#politeia:decred.org channel.
`

type userLockedResetPasswordEmailTemplateData struct {
	Link  string
	Email string
}

const templateUserLockedResetPasswordRaw = `
Your account was locked due to too many login attempts. You need to reset your
password in order to unlock your account:

{{.Link}}

You are receiving this email because someone made too many login attempts for
{{.Email}} on Politeia. If that was not you, please notify Politeia administrators.
`

type userPasswordChangedTemplateData struct {
	Email string
}

const templateUserPasswordChangedRaw = `
You are receiving this email to notify you that your password has changed for 
{{.Email}} on Politeia. If you did not perform this action, it is possible that 
your account has been compromised. Please contact Politeia administrators 
through Matrix on the #politeia:decred.org channel for further instructions.
`

// CMS events
type newInviteUserEmailTemplateData struct {
	Email string
	Link  string
}

const templateInviteNewUserEmailRaw = `
You are invited to join Decred as a contractor! To complete your registration, you will need to use the following link and register on the CMS site:

{{.Link}}

You are receiving this email because {{.Email}} was used to be invited to Decred's Contractor Management System.
If you do not recognize this, please ignore this email.
`

type approveDCCUserEmailTemplateData struct {
	Email string
	Link  string
}

const templateApproveDCCUserEmailRaw = `
Congratulations! Your Decred Contractor Clearance Proposal has been approved! 

You are now a fully registered contractor and may now submit invoices.  You should also be receiving an invitation to the contractors room on matrix.  
If you have any questions please feel free to ask them there.

You are receiving this email because {{.Email}} was used to be invited to Decred's Contractor Management System.
If you do not recognize this, please ignore this email.
`

type newInvoiceStatusUpdateTemplate struct {
	Token string
}

const templateNewInvoiceStatusUpdateRaw = `
An invoice's status has been updated, please login to cms.decred.org to review the changes.

Updated Invoice Token: {{.Token}}

Regards,
Contractor Management System
`

type newDCCSubmittedTemplateData struct {
	Link string
}

const templateNewDCCSubmittedRaw = `
A new DCC has been submitted.

{{.Link}}

Regards,
Contractor Management System
`

type newDCCSupportOpposeTemplateData struct {
	Link string
}

const templateNewDCCSupportOpposeRaw = `
A DCC has received new support or opposition.

{{.Link}}

Regards,
Contractor Management System
`

type invoiceNotificationEmailData struct {
	Username string
	Month    string
	Year     int
}

const templateInvoiceNotificationRaw = `
{{.Username}},

You have not yet submitted an invoice for {{.Month}} {{.Year}}.  Please do so as soon as possible, so your invoice may be reviewed and paid out in a timely manner.

Regards,
Contractor Management System
`

const templateNewInvoiceCommentRaw = `
An administrator has submitted a new comment to your invoice, please login to cms.decred.org to view the message.
`
