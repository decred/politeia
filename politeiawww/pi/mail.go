// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"bytes"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"text/template"

	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
)

const (
	// The following routes are used in notification emails to direct
	// the user to the correct GUI pages.
	guiRouteRecordDetails = "/record/{token}"
	guiRouteRecordComment = "/record/{token}/comments/{id}"
)

type proposalNew struct {
	Username string // Author username
	Name     string // Proposal name
	Link     string // GUI proposal details URL
}

var proposalNewText = `
A new proposal has been submitted on Politeia by {{.Username}}:

{{.Name}}
{{.Link}}
`

var proposalNewTmpl = template.Must(
	template.New("proposalNew").Parse(proposalNewText))

func (p *Pi) mailNtfnProposalNew(token, name, username string, emails []string) error {
	route := strings.Replace(guiRouteRecordDetails, "{token}", token, 1)
	u, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	tmplData := proposalNew{
		Username: username,
		Name:     name,
		Link:     u.String(),
	}

	subject := "New Proposal Submitted " + token
	body, err := populateTemplate(proposalNewTmpl, tmplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, emails)
}

type proposalEdit struct {
	Name     string // Proposal name
	Version  uint32 // Proposal version
	Username string // Author username
	Link     string // GUI proposal details URL
}

var proposalEditText = `
A proposal by {{.Username}} has just been edited:

{{.Name}} (Version {{.Version}})
{{.Link}}
`

var proposalEditTmpl = template.Must(
	template.New("proposalEdit").Parse(proposalEditText))

func (p *Pi) mailNtfnProposalEdit(token string, version uint32, name, username string, emails []string) error {
	route := strings.Replace(guiRouteRecordDetails, "{token}", token, 1)
	u, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	tmplData := proposalEdit{
		Name:     name,
		Version:  version,
		Username: username,
		Link:     u.String(),
	}

	subject := "Proposal Edited " + token
	body, err := populateTemplate(proposalEditTmpl, tmplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, emails)
}

type proposalPublished struct {
	Name string // Proposal name
	Link string // GUI proposal details URL
}

var proposalPublishedTmpl = template.Must(
	template.New("proposalPublished").Parse(proposalPublishedText))

var proposalPublishedText = `
A new proposal has just been published on Politeia.

{{.Name}}
{{.Link}}
`

func (p *Pi) mailNtfnProposalSetStatus(token, name string, status rcv1.RecordStatusT, emails []string) error {
	route := strings.Replace(guiRouteRecordDetails, "{token}", token, 1)
	u, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	var (
		subject string
		body    string
	)
	switch status {
	case rcv1.RecordStatusPublic:
		subject = "New Proposal Published " + token
		tmplData := proposalPublished{
			Name: name,
			Link: u.String(),
		}
		body, err = populateTemplate(proposalPublishedTmpl, tmplData)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("no mail ntfn for status %v", status)
	}

	return p.mail.SendToUsers(subject, body, emails)
}

type proposalPublishedToAuthor struct {
	Name string // Proposal name
	Link string // GUI proposal details URL
}

var proposalPublishedToAuthorText = `
Your proposal has just been made public on Politeia!

Your proposal has now entered the discussion phase where the community can leave comments and provide feedback.  Be sure to keep an eye out for new comments and to answer any questions that the community may have.  You can edit your proposal at any point prior to the start of voting.

Once you feel that enough time has been given for discussion you may authorize the vote to commence on your proposal.  An admin is not able to start the voting process until you explicitly authorize it.  You can authorize a proposal vote by opening the proposal page and clicking on the authorize vote button.

{{.Name}}
{{.Link}}

If you have any questions, drop by the proposals channel on matrix.
https://chat.decred.org/#/room/#proposals:decred.org
`
var proposalPublishedToAuthorTmpl = template.Must(
	template.New("proposalPublishedToAuthor").
		Parse(proposalPublishedToAuthorText))

type proposalCensoredToAuthor struct {
	Name   string // Proposal name
	Reason string // Reason for censoring
}

var proposalCensoredToAuthorText = `
Your proposal on Politeia has been censored.

{{.Name}}
Reason: {{.Reason}}
`

var proposalCensoredToAuthorTmpl = template.Must(
	template.New("proposalCensoredToAuthor").
		Parse(proposalCensoredToAuthorText))

func (p *Pi) mailNtfnProposalSetStatusToAuthor(token, name string, status rcv1.RecordStatusT, reason, authorEmail string) error {
	route := strings.Replace(guiRouteRecordDetails, "{token}", token, 1)
	u, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	var (
		subject string
		body    string
	)
	switch status {
	case rcv1.RecordStatusPublic:
		subject = "Your Proposal Has Been Published " + token
		tmplData := proposalPublishedToAuthor{
			Name: name,
			Link: u.String(),
		}
		body, err = populateTemplate(proposalPublishedToAuthorTmpl, tmplData)
		if err != nil {
			return err
		}

	case rcv1.RecordStatusCensored:
		subject = "Your Proposal Has Been Censored " + token
		tmplData := proposalCensoredToAuthor{
			Name:   name,
			Reason: reason,
		}
		body, err = populateTemplate(proposalCensoredToAuthorTmpl, tmplData)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("no author notification for prop status %v", status)
	}

	return p.mail.SendToUsers(subject, body, []string{authorEmail})
}

type commentNewToProposalAuthor struct {
	Username string // Comment author username
	Name     string // Proposal name
	Link     string // Comment link
}

var commentNewToProposalAuthorText = `
{{.Username}} has commented on your proposal "{{.Name}}".

{{.Link}}
`

var commentNewToProposalAuthorTmpl = template.Must(
	template.New("commentNewToProposalAuthor").
		Parse(commentNewToProposalAuthorText))

func (p *Pi) mailNtfnCommentNewToProposalAuthor(token string, commentID uint32, commentUsername, proposalName, proposalAuthorEmail string) error {
	cid := strconv.FormatUint(uint64(commentID), 10)
	route := strings.Replace(guiRouteRecordComment, "{token}", token, 1)
	route = strings.Replace(route, "{id}", cid, 1)

	u, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	subject := "New Comment On Your Proposal " + token
	tmplData := commentNewToProposalAuthor{
		Username: commentUsername,
		Name:     proposalName,
		Link:     u.String(),
	}
	body, err := populateTemplate(commentNewToProposalAuthorTmpl, tmplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, []string{proposalAuthorEmail})
}

type commentReply struct {
	Username string // Comment author username
	Name     string // Proposal name
	Link     string // Comment link
}

var commentReplyText = `
{{.Username}} has replied to your comment on "{{.Name}}".

{{.Link}}
`

var commentReplyTmpl = template.Must(
	template.New("commentReply").Parse(commentReplyText))

func (p *Pi) mailNtfnCommentReply(token string, commentID uint32, commentUsername, proposalName, parentAuthorEmail string) error {
	cid := strconv.FormatUint(uint64(commentID), 10)
	route := strings.Replace(guiRouteRecordComment, "{token}", token, 1)
	route = strings.Replace(route, "{id}", cid, 1)

	u, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	subject := "New Reply To Your Comment " + token
	tmplData := commentReply{
		Username: commentUsername,
		Name:     proposalName,
		Link:     u.String(),
	}
	body, err := populateTemplate(commentReplyTmpl, tmplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, []string{parentAuthorEmail})
}

type voteAuthorized struct {
	Name string // Proposal name
	Link string // GUI proposal details url
}

var voteAuthorizedText = `
A proposal vote has been authorized.

{{.Name}}
{{.Link}}
`

var voteAuthorizedTmpl = template.Must(
	template.New("voteAuthorized").Parse(voteAuthorizedText))

func (p *Pi) mailNtfnVoteAuthorized(token, name string, emails []string) error {
	route := strings.Replace(guiRouteRecordDetails, "{token}", token, 1)
	u, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	subject := "Proposal Vote Authorized " + token
	tmplData := voteAuthorized{
		Name: name,
		Link: u.String(),
	}
	body, err := populateTemplate(voteAuthorizedTmpl, tmplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, emails)
}

type voteStarted struct {
	Name string // Proposal name
	Link string // GUI proposal details url
}

const voteStartedText = `
Voting has started on a Politeia proposal.

{{.Name}}
{{.Link}}
`

var voteStartedTmpl = template.Must(
	template.New("voteStarted").Parse(voteStartedText))

func (p *Pi) mailNtfnVoteStarted(token, name string, emails []string) error {
	route := strings.Replace(guiRouteRecordDetails, "{token}", token, 1)
	u, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	subject := "Voting Started for Proposal " + token
	tmplData := voteStarted{
		Name: name,
		Link: u.String(),
	}
	body, err := populateTemplate(voteStartedTmpl, tmplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, emails)
}

type voteStartedToAuthor struct {
	Name string // Proposal name
	Link string // GUI proposal details url
}

const voteStartedToAuthorText = `
Voting has just started on your Politeia proposal.

{{.Name}}
{{.Link}}
`

var voteStartedToAuthorTmpl = template.Must(
	template.New("voteStartedToAuthor").Parse(voteStartedToAuthorText))

func (p *Pi) mailNtfnVoteStartedToAuthor(token, name, email string) error {
	route := strings.Replace(guiRouteRecordDetails, "{token}", token, 1)
	u, err := url.Parse(p.cfg.WebServerAddress + route)
	if err != nil {
		return err
	}

	subject := "Voting Has Started On Your Proposal " + token
	tmplData := voteStartedToAuthor{
		Name: name,
		Link: u.String(),
	}
	body, err := populateTemplate(voteStartedToAuthorTmpl, tmplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, []string{email})
}

func populateTemplate(tmpl *template.Template, tmplData interface{}) (string, error) {
	var b bytes.Buffer
	err := tmpl.Execute(&b, tmplData)
	if err != nil {
		return "", err
	}
	return b.String(), nil
}
