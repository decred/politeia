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

const (
	// defaultRateLimitPeriod is the default rate limit period that is
	// used when initializing a new client. This value is configurable
	// so that it can be updated during tests.
	defaultRateLimitPeriod = 24 * time.Hour
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
	disabled    bool          // Has email been disabled

	// rateLimit is the maximum number of emails that can be sent to
	// any individual user during a single rateLimitPeriod. Once the
	// rate limit is hit the user must wait one rateLimitPeriod before
	// the will be sent any additional emails. The rate limit is only
	// applied to certain client methods.
	rateLimit       int
	rateLimitPeriod time.Duration
}

// IsEnabled returns whether the mail server is enabled.
//
// This function satisfies the Mailer interface.
func (c *client) IsEnabled() bool {
	return !c.disabled
}

// SendTo sends an email to a list of recipient email addresses.
// This function does not rate limit emails and a recipient does
// does not need to correspond to a politeiawww user. This function
// can be used to send emails to sysadmins or similar cases.
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

// SendToUsers sends an email to a list of recipient email
// addresses. The recipient MUST correspond to a politeiawww user
// in the database for the email to be sent. This function rate
// limits the number of emails that can be sent to any individual
// user over a 24 hour period. If a recipient is provided that does
// not correspond to a politeiawww user, the email is simply
// skipped. An error is not returned.
//
// This function satisfies the Mailer interface.
func (c *client) SendToUsers(subjects, body string, recipients map[uuid.UUID]string) error {
	if c.disabled || len(recipients) == 0 {
		return nil
	}

	filtered, err := c.filterRecipients(recipients)
	if err != nil {
		return err
	}

	// Handle valid recipients.
	err = c.SendTo(subjects, body, filtered.valid)
	if err != nil {
		return err
	}

	// Handle warning email recipients.
	err = c.SendTo(limitEmailSubject, limitEmailBody, filtered.warning)
	if err != nil {
		return err
	}

	// Update email histories in the db.
	err = c.mailerDB.EmailHistoriesSave(filtered.histories)
	if err != nil {
		return err
	}

	return nil
}

// filteredRecipients is returned by the filteredRecipients function and
// contains the recipients that should receive some sort of email notification.
//
// Users that have already hit the email rate limit are not included in this
// reply.
//
// If a user has previously hit the rate limit, but a full rate limit period
// has passed, their email history is reset and they will be included in the
// reply.
type filteredRecipients struct {
	// valid contains the email addresses of the users that have not
	// hit the email rate limit and are eligible to receive an email.
	valid []string

	// warning contains the email addresses of the users that have hit
	// the email rate limit during this invocation and should be sent
	// the rate limit warning email.
	warning []string

	// histories contains the updated email histories of the users in
	// the valid and warning lists.
	histories map[uuid.UUID]user.EmailHistory
}

// filterRecipients filters the users map[userid]email argument into the
// filteredRecipients struct.
func (c *client) filterRecipients(users map[uuid.UUID]string) (*filteredRecipients, error) {
	// Compile user IDs from recipients and get their email histories.
	ids := make([]uuid.UUID, 0, len(users))
	for id := range users {
		ids = append(ids, id)
	}
	hs, err := c.mailerDB.EmailHistoriesGet(ids)
	if err != nil {
		return nil, err
	}

	// Divide recipients into valid and warning recipients, and parse their
	// new email history.
	var recipients filteredRecipients
	recipients.histories = make(map[uuid.UUID]user.EmailHistory, len(users))
	for userID, email := range users {
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
		history.Timestamps = filterTimestamps(history.Timestamps,
			c.rateLimitPeriod)

		if len(history.Timestamps) >= c.rateLimit {
			// Rate limit has been hit. If limit warning email has not yet
			// been sent, add user to warning recipients and update email
			// history.
			if !history.LimitWarningSent {
				recipients.warning = append(recipients.warning, email)
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

// The limit email is sent to users as a warning when they hit the email rate
// limit.
const limitEmailSubject = "Email Rate Limit Hit"
const limitEmailBody = `
Your email rate limit for the past 24 hours has been hit. This measure is used to avoid malicious users from spamming Politeia's email server. You will not receive any notification emails for 24 hours.

We apologize for any inconvenience.
`

// NewClient returns a new client.
func NewClient(host, user, password, emailAddress, certPath string, skipVerify bool, rateLimit int, db user.MailerDB) (*client, error) {
	// Email is considered disabled if any of the required user
	// credentials are missing.
	if host == "" || user == "" || password == "" {
		log.Infof("Mail: DISABLED")
		return &client{
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
		smtp:            smtp,
		mailName:        a.Name,
		mailAddress:     a.Address,
		mailerDB:        db,
		disabled:        false,
		rateLimit:       rateLimit,
		rateLimitPeriod: defaultRateLimitPeriod,
	}, nil
}
