// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

type newUserEmailTemplateData struct {
	Username string
	Link     string
	Email    string
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

type newProposalSubmittedTemplateData struct {
	Link     string
	Name     string
	Username string
	Email    string
}

type proposalEditedTemplateData struct {
	Link     string
	Name     string
	Version  string
	Username string
}

type proposalVoteStartedTemplateData struct {
	Link     string
	Name     string
	Username string
}

type proposalStatusChangeTemplateData struct {
	Link               string
	Name               string
	Username           string
	StatusChangeReason string
}

type proposalVoteAuthorizedTemplateData struct {
	Link     string
	Name     string
	Username string
	Email    string
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
 on Politeia. If you did not perform this action, please contact Politeia
administrators.
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

const templateNewProposalSubmittedRaw = `
A new proposal has been submitted on Politeia by {{.Username}} ({{.Email}}):

{{.Name}}
{{.Link}}
`

const templateProposalVettedRaw = `
A new proposal has just been approved on Politeia, authored by {{.Username}}:

{{.Name}}
{{.Link}}
`

const templateProposalEditedRaw = `
A proposal by {{.Username}} has just been edited:

{{.Name}} (Version: {{.Version}})
{{.Link}}
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

const templateProposalVettedForAuthorRaw = `
Your proposal has just been approved on Politeia!

You will need to authorize a proposal vote before an administrator will be
allowed to start the voting period on your proposal.  You can authorize a
proposal vote by opening the proposal page and clicking on the "Authorize
Voting to Start" button.

You must authorize a proposal vote within 14 days.  If you fail to do so, your
proposal will be considered abandoned.

{{.Name}}
{{.Link}}
`

const templateProposalCensoredForAuthorRaw = `
Your proposal on Politeia has been censored:

{{.Name}}
{{.Link}}
Reason: {{.StatusChangeReason}}
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
