// Copyright (c) 2021 The Decred developers
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
	"github.com/google/uuid"
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
func (c *client) SendToUsers(subjects, body string, recipients map[uuid.UUID]string) error {
	filtered, err := c.filterRecipients(recipients)
	if err != nil {
		return err
	}

	// Handle valid recipients.
	err = c.SendTo(subjects, body, filtered.valid)
	if err != nil {
		return err
	}

	// Handle invalid recipients.
	err = c.SendTo(limitEmailSubject, limitEmailBody, filtered.invalid)
	if err != nil {
		return err
	}

	// Update email histories on db.
	err = c.mailerDB.EmailHistoriesSave(filtered.histories)
	if err != nil {
		return err
	}

	return nil
}

// filteredRecipients contains the filtered recipients divided into valid,
// those that are able to receive emails, and invalid, those that have hit
// the email rate limit, but have not yet received the warning email. It will
// also contains the updated email histories for each user email present on the
// valid and invalid lists.
type filteredRecipients struct {
	valid     []string
	invalid   []string
	histories map[uuid.UUID]user.EmailHistory
}

// filterRecipients filters the users map[userid]email argument into the
// filteredRecipients struct.
func (c *client) filterRecipients(rs map[uuid.UUID]string) (*filteredRecipients, error) {
	// Sanity check.
	if len(rs) == 0 {
		return &filteredRecipients{}, nil
	}

	// Compile user IDs from recipients and get their email histories.
	ids := make([]uuid.UUID, 0, len(rs))
	for id := range rs {
		ids = append(ids, id)
	}
	hs, err := c.mailerDB.EmailHistoriesGet(ids)
	if err != nil {
		return nil, err
	}

	// Divide recipients into valid and invalid recipients, and parse their
	// new email history.
	var recipients filteredRecipients
	recipients.histories = make(map[uuid.UUID]user.EmailHistory, len(rs))
	for userID, email := range rs {
		history, ok := hs[userID]
		if !ok {
			// User does not have a mail history yet, add user to valid
			// recipients and create his email history.
			recipients.histories[userID] = user.EmailHistory{
				Timestamps:       []int64{time.Now().Unix()},
				LimitWarningSent: false,
			}
			recipients.valid = append(recipients.valid, email)
			continue
		}

		// Filter timestamps for the past 24h.
		history.Timestamps = filterTimestamps(history.Timestamps, cooldown)

		if len(history.Timestamps) >= c.limit {
			// Rate limit has been hit. If limit warning email has not yet
			// been sent, add user to invalid recipients and update email
			// history.
			if !history.LimitWarningSent {
				recipients.invalid = append(recipients.invalid, email)
				history.LimitWarningSent = true
				recipients.histories[userID] = history
			}
			continue
		}

		// Rate limit has not been hit, add user to valid recipients and
		// update email history.
		recipients.valid = append(recipients.valid, email)
		history.Timestamps = append(history.Timestamps, time.Now().Unix())
		history.LimitWarningSent = false
		recipients.histories[userID] = history
	}

	return &recipients, nil
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

// NewClient returns a new client.
func NewClient(host, user, password, emailAddress, certPath string, skipVerify bool, limit int, db user.MailerDB) (*client, error) {
	// Email is considered disabled if any of the required user
	// credentials are missing.
	if host == "" || user == "" || password == "" {
		log.Infof("Mail: DISABLED")
		return &client{
			disabled: true,
			mailerDB: db,
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
