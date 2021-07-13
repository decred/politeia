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
	"time"

	"github.com/dajohi/goemail"
	"github.com/decred/politeia/politeiawww/user"
)

// client provides an SMTP client for sending emails from a preset email
// address.
//
// client implements the Mailer interface.
type client struct {
	smtp        *goemail.SMTP // SMTP server
	mailName    string        // From name
	mailAddress string        // From email address
	mailerDB    user.MailerDB // User mailer database in www
	limit       int           // Email rate limit
	disabled    bool          // Has email been disabled
}

// cooldown is the elapsed time used to reset a user's limited email
// history.
const cooldown = 24 * time.Hour

// IsEnabled returns whether the mail server is enabled.
//
// This function satisfies the Mailer interface.
func (c *client) IsEnabled() bool {
	return !c.disabled
}

// SendTo sends an email with the given subject and body to the provided list
// of email addresses.
//
// This function satisfies the Mailer interface.
func (c *client) SendTo(subject, body string, recipients []string) error {
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

// SendToUsers sends an email with the given subject and body to the provided list
// of email addresses. This adds an email rate limit functionality in order
// to avoid spamming from malicious users.
//
// This function satisfies the Mailer interface.
func (c *client) SendToUsers(subjects, body string, recipients []string) error {
	valid, invalid, histories, err := c.filterRecipients(recipients)
	if err != nil {
		return err
	}

	// Handle valid recipients.
	if len(valid) > 0 {
		err := c.SendTo(subjects, body, valid)
		if err != nil {
			return err
		}
	}

	// Handle invalid recipients.
	if len(invalid) > 0 {
		err = c.SendTo(limitEmailSubject, limitEmailBody, invalid)
		if err != nil {
			return err
		}
	}

	// Update email histories on db.
	if len(histories) > 0 {
		c.mailerDB.EmailHistoriesSave(histories)
	}

	return nil
}

// filterRecipients divides recipients into valid, those that are able to
// receive emails, and invalid, those that have hit the email rate limit,
// but have not yet received the warning email. It also returns an updated
// email history for each user to be saved on the db.
func (c *client) filterRecipients(rs []string) ([]string, []string, map[string]user.EmailHistory, error) {
	// Sanity check
	if len(rs) == 0 {
		return nil, nil, nil, nil
	}

	// Get email histories for recipients
	hs, err := c.mailerDB.EmailHistoriesGet(rs)
	if err != nil {
		return nil, nil, nil, err
	}

	// Divide recipients into valid and invalid recipients, and parse their
	// new email history.
	var (
		valid     []string
		invalid   []string
		histories = make(map[string]user.EmailHistory, len(rs))
	)
	for _, email := range rs {
		history, ok := hs[email]
		if !ok {
			// User does not have a mail history yet, add user to valid
			// recipients and create his email history.
			histories[email] = user.EmailHistory{
				Timestamps:       []int64{time.Now().Unix()},
				LimitWarningSent: false,
			}
			valid = append(valid, email)
			continue
		}

		// Filter timestamps for the past 24h.
		history.Timestamps = filterTimestamps(history.Timestamps, cooldown)

		if len(history.Timestamps) >= c.limit {
			// Rate limit has been hit. If limit warning email has not yet
			// been sent, add user to invalid recipients and update email
			// history.
			if !history.LimitWarningSent {
				invalid = append(invalid, email)
				history.LimitWarningSent = true
				histories[email] = history
			}
			continue
		}

		// Rate limit has not been hit, add user to valid recipients and
		// update email history.
		valid = append(valid, email)
		history.Timestamps = append(history.Timestamps, time.Now().Unix())
		history.LimitWarningSent = false
		histories[email] = history
	}

	return valid, invalid, histories, nil
}

// filterTimestamps filters out timestamps from the passed in slice that comes
// before the specified delta time duration.
func filterTimestamps(in []int64, delta time.Duration) []int64 {
	before := time.Now().Add(-delta)
	out := make([]int64, 0, len(in))

	for _, ts := range in {
		timestamp := time.Unix(ts, 0)
		if timestamp.Before(before) {
			continue
		}
		out = append(out, ts)
	}

	return out
}

// Limit warning email texts that are sent to invalid users.
const limitEmailSubject = "Email Rate Limit Hit"
const limitEmailBody = `
Your email rate limit for the past 24h has been hit. This measure is used to avoid malicious users spamming Politeia's email server. 
	
We apologize for any inconvenience.
`

// newClient returns a new client.
func newClient(host, user, password, emailAddress, certPath string, skipVerify bool, db user.MailerDB, limit int) (*client, error) {
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
		InsecureSkipVerify: true,
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

	return &client{
		smtp:        smtp,
		mailName:    a.Name,
		mailAddress: a.Address,
		mailerDB:    db,
		limit:       limit,
		disabled:    false,
	}, nil
}
