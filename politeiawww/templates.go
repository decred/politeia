// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import "text/template"

var (
	templateProposalVoteStarted = template.Must(
		template.New("proposal_vote_started_template").Parse(templateProposalVoteStartedRaw))
	templateProposalVoteAuthorized = template.Must(
		template.New("proposal_vote_authorized_template").Parse(templateProposalVoteAuthorizedRaw))
	templateProposalVoteStartedForAuthor = template.Must(
		template.New("proposal_vote_started_for_author_template").Parse(templateProposalVoteStartedForAuthorRaw))
	templateCommentReplyOnProposal = template.Must(
		template.New("comment_reply_on_proposal").Parse(templateCommentReplyOnProposalRaw))
	templateCommentReplyOnComment = template.Must(
		template.New("comment_reply_on_comment").Parse(templateCommentReplyOnCommentRaw))
)

// Proposal submitted
type tmplDataProposalSubmitted struct {
	Username string // Author username
	Name     string // Proposal name
	Link     string // GUI proposal details url
}

const tmplTextProposalSubmitted = `
A new proposal has been submitted on Politeia by {{.Username}}:

{{.Name}}
{{.Link}}
`

var tmplProposalSubmitted = template.Must(
	template.New("proposal_submitted").
		Parse(tmplTextProposalSubmitted))

// Proposal edited
type tmplDataProposalEdited struct {
	Name     string // Proposal name
	Version  string // ProposalVersion
	Username string // Author username
	Link     string // GUI proposal details url
}

const tmplTextProposalEdited = `
A proposal by {{.Username}} has just been edited:

{{.Name}} (Version: {{.Version}})
{{.Link}}
`

var tmplProposalEdited = template.Must(
	template.New("proposal_edited").
		Parse(tmplTextProposalEdited))

// Proposal status change - Vetted - Send to author
type tmplDataProposalVettedForAuthor struct {
	Name string // Proposal name
	Link string // GUI proposal details url
}

const tmplTextProposalVettedForAuthor = `
Your proposal has just been approved on Politeia!

You will need to authorize a proposal vote before an administrator will be
allowed to start the voting period on your proposal.  You can authorize a
proposal vote by opening the proposal page and clicking on the "Authorize
Voting to Start" button.

You should allow sufficient time for the community to discuss your proposal
before authorizing the vote.

{{.Name}}
{{.Link}}
`

var tmplProposalVettedForAuthor = template.Must(
	template.New("proposal_vetted_for_author").
		Parse(tmplTextProposalVettedForAuthor))

// Proposal status change - Censored - Send to author
type tmplDataProposalCensoredForAuthor struct {
	Name   string // Proposal name
	Reason string // Reason for censoring
	Link   string // GUI proposal details url
}

const tmplTextProposalCensoredForAuthor = `
Your proposal on Politeia has been censored:

{{.Name}}
Reason: {{.Reason}}
{{.Link}}
`

var tmplProposalCensoredForAuthor = template.Must(
	template.New("proposal_censored_for_author").
		Parse(tmplTextProposalCensoredForAuthor))

// Proposal status change - Vetted - Send to users
type tmplDataProposalVetted struct {
	Name string
	Link string
}

const tmplTextProposalVetted = `
A new proposal has just been published on Politeia.

{{.Name}}
{{.Link}}
`

var tmplProposalVetted = template.Must(
	template.New("proposal_vetted").
		Parse(tmplTextProposalVetted))

type invoiceNotificationEmailData struct {
	Username string
	Month    string
	Year     int
}

type newUserEmailTemplateData struct {
	Username string
	Link     string
	Email    string
}

type newInviteUserEmailTemplateData struct {
	Email string
	Link  string
}

type approveDCCUserEmailTemplateData struct {
	Email string
	Link  string
}

type updateUserKeyEmailTemplateData struct {
	Link      string
	PublicKey string
	Email     string
}

type resetPasswordEmailTemplateData struct {
	Link  string
	Email string
}

type userLockedResetPasswordEmailTemplateData struct {
	Link  string
	Email string
}

type userPasswordChangedTemplateData struct {
	Email string
}

type proposalVoteStartedTemplateData struct {
	Link     string // GUI proposal details url
	Name     string // Proposal name
	Username string // Author username
}

type proposalVoteAuthorizedTemplateData struct {
	Link     string // GUI proposal details url
	Name     string // Proposal name
	Username string // Author username
	Email    string // Author email
}

type commentReplyOnProposalTemplateData struct {
	Commenter    string
	ProposalName string
	CommentLink  string
}

type commentReplyOnCommentTemplateData struct {
	Commenter    string
	ProposalName string
	CommentLink  string
}

type newInvoiceCommentTemplateData struct {
}

type newInvoiceStatusUpdateTemplate struct {
	Token string
}

type newDCCSubmittedTemplateData struct {
	Link string
}

type newDCCSupportOpposeTemplateData struct {
	Link string
}

const templateNewUserEmailRaw = `
Thanks for joining Politeia, {{.Username}}!

Click the link below to verify your email and complete your registration:

{{.Link}}

You are receiving this email because {{.Email}} was used to register for Politeia.
If you did not perform this action, please ignore this email.
`

const templateResetPasswordEmailRaw = `
Click the link below to continue resetting your password:

{{.Link}}

You are receiving this email because a password reset was initiated for {{.Email}}
on Politeia. If you did not perform this action, it is possible that your account has been
compromised. Please contact Politeia administrators through Matrix on the
#politeia:decred.org channel.
`

const templateUserPasswordChangedRaw = `
You are receiving this email to notify you that your password has changed for 
{{.Email}} on Politeia. If you did not perform this action, it is possible that 
your account has been compromised. Please contact Politeia administrators 
through Matrix on the #politeia:decred.org channel for further instructions.
`

const templateUpdateUserKeyEmailRaw = `
Click the link below to verify your new identity:

{{.Link}}

You are receiving this email because a new identity (public key: {{.PublicKey}})
was generated for {{.Email}} on Politeia. If you did not perform this action,
please contact Politeia administrators.
`

const templateUserLockedResetPasswordRaw = `
Your account was locked due to too many login attempts. You need to reset your
password in order to unlock your account:

{{.Link}}

You are receiving this email because someone made too many login attempts for
{{.Email}} on Politeia. If that was not you, please notify Politeia administrators.
`

const templateProposalVoteStartedRaw = `
Voting has started for the following proposal on Politeia, authored by {{.Username}}:

{{.Name}}
{{.Link}}
`

const templateProposalVoteAuthorizedRaw = `
Voting has been authorized for the following proposal on Politeia by {{.Username}} ({{.Email}}):

{{.Name}}
{{.Link}}
`

const templateProposalVoteStartedForAuthorRaw = `
Voting has just started for your proposal on Politeia!

{{.Name}}
{{.Link}}
`

const templateCommentReplyOnProposalRaw = `
{{.Commenter}} has commented on your proposal!

Proposal: {{.ProposalName}}
Comment: {{.CommentLink}}
`

const templateCommentReplyOnCommentRaw = `
{{.Commenter}} has replied to your comment!

Proposal: {{.ProposalName}}
Comment: {{.CommentLink}}
`

const templateInviteNewUserEmailRaw = `
You are invited to join Decred as a contractor! To complete your registration, you will need to use the following link and register on the CMS site:

{{.Link}}

You are receiving this email because {{.Email}} was used to be invited to Decred's Contractor Management System.
If you do not recognize this, please ignore this email.
`

const templateApproveDCCUserEmailRaw = `
Congratulations! Your Decred Contractor Clearance Proposal has been approved! 

You are now a fully registered contractor and may now submit invoices.  You should also be receiving an invitation to the contractors room on matrix.  
If you have any questions please feel free to ask them there.

You are receiving this email because {{.Email}} was used to be invited to Decred's Contractor Management System.
If you do not recognize this, please ignore this email.
`

const templateInvoiceNotificationRaw = `
{{.Username}},

You have not yet submitted an invoice for {{.Month}} {{.Year}}.  Please do so as soon as possible, so your invoice may be reviewed and paid out in a timely manner.

Regards,
Contractor Management System
`

const templateNewInvoiceCommentRaw = `
An administrator has submitted a new comment to your invoice, please login to cms.decred.org to view the message.
`

const templateNewInvoiceStatusUpdateRaw = `
An invoice's status has been updated, please login to cms.decred.org to review the changes.

Updated Invoice Token: {{.Token}}

Regards,
Contractor Management System
`

const templateNewDCCSubmittedRaw = `
A new DCC has been submitted.

{{.Link}}

Regards,
Contractor Management System
`

const templateNewDCCSupportOpposeRaw = `
A DCC has received new support or opposition.

{{.Link}}

Regards,
Contractor Management System
`
