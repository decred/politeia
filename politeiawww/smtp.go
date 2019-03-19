package main

import (
	"crypto/tls"
	"fmt"
	"net/mail"
	"net/url"

	"github.com/dajohi/goemail"
)

// smtp is a SMTP client for sending Politeia emails.
type smtp struct {
	client      *goemail.SMTP // SMTP client
	mailName    string        // Email address name
	mailAddress string        // Email address
	disabled    bool          // Has email been disabled
}

// sendEmail sends an email with the given subject and body, and the caller
// must supply a function which is used to add email addresses to send the
// email to.
func (s *smtp) sendEmail(subject, body string, addToAddressesFn func(*goemail.Message) error) error {
	if s.disabled {
		return nil
	}

	msg := goemail.NewMessage(s.mailAddress, subject, body)
	err := addToAddressesFn(msg)
	if err != nil {
		return err
	}

	msg.SetName(s.mailName)
	return s.client.Send(msg)
}

// newSMTP returns a new smtp context.
func newSMTP(host, user, password, emailAddress string) (*smtp, error) {
	// Check if email has been disabled
	if host == "" || user == "" || password == "" {
		return &smtp{
			disabled: true,
		}, nil
	}

	// Parse mail host
	h := fmt.Sprintf("smtps://%v:%v@%v", user, password, host)
	u, err := url.Parse(h)
	if err != nil {
		return nil, err
	}

	// Parse email address
	a, err := mail.ParseAddress(emailAddress)
	if err != nil {
		return nil, err
	}

	// Initialize SMTP client
	client, err := goemail.NewSMTP(u.String(), &tls.Config{})
	if err != nil {
		return nil, err
	}

	return &smtp{
		client:      client,
		mailName:    a.Name,
		mailAddress: a.Address,
		disabled:    false,
	}, nil
}
