// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package mail

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/mail"
	"net/url"

	"github.com/dajohi/goemail"
)

// Client provides an SMTP client for sending emails from a preset email
// address.
type Client struct {
	smtp        *goemail.SMTP // SMTP server
	mailName    string        // From name
	mailAddress string        // From email address
	disabled    bool          // Has email been disabled
}

// IsEnabled returns whether the mail server is enabled.
func (c *Client) IsEnabled() bool {
	return !c.disabled
}

// SendTo sends an email with the given subject and body to the provided list
// of email addresses.
func (c *Client) SendTo(subject, body string, recipients []string) error {
	if c.disabled || len(recipients) == 0 {
		return nil
	}

	// Setup email
	msg := goemail.NewMessage(c.mailAddress, subject, body)
	msg.SetName(c.mailName)

	// Add all recipients to BCC
	for _, v := range recipients {
		msg.AddBCC(v)
	}

	return c.smtp.Send(msg)
}

// New returns a new mail Client.
func New(host, user, password, emailAddress, certPath string, skipVerify bool) (*Client, error) {
	// Email is considered disabled if any of the required user
	// credentials are mising.
	if host == "" || user == "" || password == "" {
		log.Infof("Email: DISABLED")
		return &Client{
			disabled: true,
		}, nil
	}

	// Parse mail host
	h := fmt.Sprintf("smtps://%v:%v@%v", user, password, host)
	u, err := url.Parse(h)
	if err != nil {
		return nil, err
	}

	log.Infof("Mail host: smtps://%v:[password]@%v", user, host)

	// Parse email address
	a, err := mail.ParseAddress(emailAddress)
	if err != nil {
		return nil, err
	}

	log.Infof("Mail address: %v", a.String())

	// Setup tls config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: skipVerify,
	}
	if !skipVerify && certPath != "" {
		cert, err := ioutil.ReadFile(certPath)
		if err != nil {
			return nil, err
		}
		certPool, err := x509.SystemCertPool()
		if err != nil {
			certPool = x509.NewCertPool()
		}
		certPool.AppendCertsFromPEM(cert)
		tlsConfig.RootCAs = certPool
	}

	// Setup smtp context
	smtp, err := goemail.NewSMTP(u.String(), tlsConfig)
	if err != nil {
		return nil, err
	}

	return &Client{
		smtp:        smtp,
		mailName:    a.Name,
		mailAddress: a.Address,
		disabled:    false,
	}, nil
}
