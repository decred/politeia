// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package pi

import (
	"bytes"
	"net/url"
	"strings"
	"text/template"
)

const (
	// TODO GUI links needs to be updated
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

	subject := "New Proposal Submitted"
	body, err := populateTemplate(proposalNewTmpl, tmplData)
	if err != nil {
		return err
	}

	return p.mail.SendTo(subject, body, emails)
}

type proposalEdit struct {
	Name     string // Proposal name
	Version  string // Proposal version
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

func (p *Pi) mailNtfnProposalEdit(token, version, name, username string, emails []string) error {
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

	subject := "Proposal Edited"
	body, err := populateTemplate(proposalEditTmpl, tmplData)
	if err != nil {
		return err
	}

	return p.mail.SendTo(subject, body, emails)
}

func populateTemplate(tpl *template.Template, tplData interface{}) (string, error) {
	var buf bytes.Buffer
	err := tpl.Execute(&buf, tplData)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
