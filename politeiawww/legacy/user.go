// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/decred/politeia/politeiad/api/v1/identity"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/decred/politeia/util"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	LoginAttemptsToLockUser = 5

	// Number of attempts until totp locks until the next window
	totpFailedAttempts = 2

	// Route to reset password at GUI
	ResetPasswordGuiRoute = "/password" // XXX what is this doing here?

	emailRegex = `^[a-zA-Z0-9.!#$%&'*+/=?^_` +
		"`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?" +
		"(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

var (
	validUsername = regexp.MustCompile(createUsernameRegex())
	validEmail    = regexp.MustCompile(emailRegex)

	// resetPasswordMinWaitTime is the minimum amount of time to wait
	// before sending a response back to the client for the reset
	// password route. This is done to prevent an attacker from being
	// able to execute a timing attack to determine if the provided
	// email address is the user's valid email address.
	resetPasswordMinWaitTime = 500 * time.Millisecond

	// loginMinWaitTime is the minimum amount of time to wait before
	// the server sends a response to the client for the login route.
	// This is done to prevent an attacker from being able to execute
	// a timing attack to determine whether the ErrorStatusInvalidLogin
	// response is specific to a bad email or a bad password.
	loginMinWaitTime = 500 * time.Millisecond
)

// processNewUser creates a new user in the db if it doesn't already
// exist and sets a verification token and expiry; the token must be
// verified before it expires. If the user already exists in the db
// and its token is expired, it generates a new one.
//
// Note that this function always returns a NewUserReply. The caller shall
// verify error and determine how to return this information upstream.
func (p *LegacyPoliteiawww) processNewUser(nu www.NewUser) (*www.NewUserReply, error) {
	log.Tracef("processNewUser: %v", nu.Username)

	// Format and validate user credentials
	nu.Email = strings.ToLower(nu.Email)
	if !validEmail.MatchString(nu.Email) {
		log.Debugf("processNewUser: invalid email '%v'", nu.Email)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusMalformedEmail,
		}
	}
	err := validatePubKey(nu.PublicKey)
	if err != nil {
		return nil, err
	}

	nu.Username = formatUsername(nu.Username)
	err = validateUsername(nu.Username)
	if err != nil {
		return nil, err
	}

	// The client should be hashing the password before
	// sending it to politeiawww. This validation is only
	// relevant if the client failed to hash the password
	// or does not include a password in the request.
	err = validatePassword(nu.Password)
	if err != nil {
		return nil, err
	}

	// Check if user already exists
	u, err := p.userByEmail(nu.Email)
	switch err {
	case nil:
		// User exists

		// Return if the user is already verified
		if u.NewUserVerificationToken == nil {
			log.Debugf("processNewUser: '%v' already verified",
				nu.Username)
			return &www.NewUserReply{}, nil
		}

		// User is not already verified. Check if the verification token
		// has expired. If the token has not expired yet, we simply return.
		// The user will have to wait until the token expires before a
		// new one will be sent. If the token has expired, we update the
		// user in the database and send the user a new token. The user
		// identity will be updated if the request specifies a new public
		// key.
		if u.NewUserVerificationExpiry > time.Now().Unix() {
			log.Debugf("processNewUser: '%v' not verified, "+
				"token not expired", nu.Username)
			return &www.NewUserReply{}, nil
		}

		// Ensure public key is unique
		usr, err := p.db.UserGetByPubKey(nu.PublicKey)
		if err != nil {
			if errors.Is(err, user.ErrUserNotFound) {
				// Pubkey is unique, but is not the same pubkey that
				// the user originally signed up with. This is fine.
				// The user's identity just needs to be updated.
				id, err := user.NewIdentity(nu.PublicKey)
				if err != nil {
					return nil, err
				}
				err = u.AddIdentity(*id)
				if err != nil {
					return nil, err
				}
			}
		} else {
			switch {
			case usr.ID.String() == u.ID.String():
				// Pubkey exists and belongs to this user. This is
				// ok. It just means that the user is requesting a
				// new verification token using the same identity
				// that they signed up with. Continue.
			default:
				// Pubkey exists and belongs to another user
				return nil, www.UserError{
					ErrorCode: www.ErrorStatusDuplicatePublicKey,
				}
			}
		}

		// Generate a new verification token
		tokenb, expiry, err := newVerificationTokenAndExpiry()
		if err != nil {
			return nil, err
		}

		// Email the verification token before updating the
		// database. If the email fails, the database won't
		// be updated.
		err = p.emailUserEmailVerify(u.Email,
			hex.EncodeToString(tokenb), u.Username)
		if err != nil {
			log.Errorf("processNewUser: mail verification "+
				"token failed for '%v': %v", u.Email, err)
			return &www.NewUserReply{}, nil
		}

		// Update user record with the verification token and
		// the new identity if one was set.
		u.NewUserVerificationToken = tokenb
		u.NewUserVerificationExpiry = expiry
		err = p.db.UserUpdate(*u)
		if err != nil {
			return nil, err
		}

		// Send reply. Only return the verification token in
		// the reply if the mail server has been disabled.
		var t string
		if !p.mail.IsEnabled() {
			t = hex.EncodeToString(u.NewUserVerificationToken)
		}
		return &www.NewUserReply{
			VerificationToken: t,
		}, nil
	case user.ErrUserNotFound:
		// User doesn't exist; continue
	default:
		// All other errors
		return nil, err
	}

	// User does not exist. Create a new user.

	// Ensure username is unique
	_, err = p.db.UserGetByUsername(nu.Username)
	switch err {
	case nil:
		// Duplicate username
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusDuplicateUsername,
		}
	case user.ErrUserNotFound:
		// Username does not exist; continue
	default:
		return nil, err
	}

	// Ensure public key is unique
	_, err = p.db.UserGetByPubKey(nu.PublicKey)
	switch err {
	case user.ErrUserNotFound:
		// Pubkey is unique; continue
	case nil:
		// Duplicate pubkey
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusDuplicatePublicKey,
		}
	default:
		// All other errors
		return nil, err
	}

	// Create user
	hashedPass, err := p.hashPassword(nu.Password)
	if err != nil {
		return nil, err
	}
	tokenb, expiry, err := newVerificationTokenAndExpiry()
	if err != nil {
		return nil, err
	}
	newUser := user.User{
		Email:                     nu.Email,
		Username:                  nu.Username,
		HashedPassword:            hashedPass,
		NewUserVerificationToken:  tokenb,
		NewUserVerificationExpiry: expiry,
	}
	id, err := user.NewIdentity(nu.PublicKey)
	if err != nil {
		return nil, err
	}
	err = newUser.AddIdentity(*id)
	if err != nil {
		return nil, err
	}

	// Try to email the verification link first; if it fails,
	// then the new user won't be created.
	//
	// This is conditional on the email server being setup.
	err = p.emailUserEmailVerify(newUser.Email,
		hex.EncodeToString(tokenb), newUser.Username)
	if err != nil {
		log.Errorf("processNewUser: mail verification token "+
			"failed for '%v': %v", newUser.Email, err)
		return &www.NewUserReply{}, nil
	}

	// Save new user to the database
	err = p.db.UserNew(newUser)
	if err != nil {
		return nil, err
	}

	// Set paywall info for the user. This had to wait until after the
	// user was already created in the db because the db sets the
	// paywall address index when the user is created, and the paywall
	// address index is used to generate the paywall info. Lookup the
	// user from the db to get the paywall address index.
	u, err = p.db.UserGetByUsername(newUser.Username)
	if err != nil {
		return nil, err
	}
	err = p.generateNewUserPaywall(u)
	if err != nil {
		return nil, err
	}

	// Update memory cache
	p.setUserEmailsCache(u.Email, u.ID)

	log.Infof("New user created: %v", u.Username)

	// Only return the verification token in the reply
	// if the mail server has been disabled.
	var t string
	if !p.mail.IsEnabled() {
		t = hex.EncodeToString(u.NewUserVerificationToken)
	}
	return &www.NewUserReply{
		VerificationToken: t,
	}, nil
}

// initUserEmailsCache initializes the userEmails cache by iterating through
// all the users in the database and adding a email-userID mapping for them.
//
// This function must be called WITHOUT the lock held.
func (p *LegacyPoliteiawww) initUserEmailsCache() error {
	p.Lock()
	defer p.Unlock()

	return p.db.AllUsers(func(u *user.User) {
		p.userEmails[u.Email] = u.ID
	})
}

// setUserEmailsCache sets a email-userID mapping in the user emails cache.
//
// This function must be called WITHOUT the lock held.
func (p *LegacyPoliteiawww) setUserEmailsCache(email string, id uuid.UUID) {
	p.Lock()
	defer p.Unlock()
	p.userEmails[email] = id
}

// userIDByEmail returns a userID given their email address.
//
// This function must be called WITHOUT the lock held.
func (p *LegacyPoliteiawww) userIDByEmail(email string) (uuid.UUID, bool) {
	p.RLock()
	defer p.RUnlock()
	id, ok := p.userEmails[email]
	return id, ok
}

// userByEmail returns a User object given their email address.
//
// This function must be called WITHOUT the lock held.
func (p *LegacyPoliteiawww) userByEmail(email string) (*user.User, error) {
	id, ok := p.userIDByEmail(email)
	if !ok {
		log.Debugf("userByEmail: email lookup failed for '%v'", email)
		return nil, user.ErrUserNotFound
	}
	return p.db.UserGetById(id)
}

// userByIDStr converts the provided userIDStr to a uuid and returns the
// corresponding user, if one it exists.
func (p *LegacyPoliteiawww) userByIDStr(userIDStr string) (*user.User, error) {
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusInvalidUUID,
		}
	}

	usr, err := p.db.UserGetById(userID)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusUserNotFound,
			}
		}
		return nil, err
	}

	return usr, nil
}

// emailUserEmailVerify sends a new user verification email to the provided
// email address. This function is not rate limited by the smtp client because
// the user is only created/updated when this function is successfully executed
// and an email with the verification token is sent to the user. This email is
// also already limited by the verification token expiry hours policy.
func (p *LegacyPoliteiawww) emailUserEmailVerify(email, token, username string) error {
	link, err := p.createEmailLink(www.RouteVerifyNewUser, email,
		token, username)
	if err != nil {
		return err
	}

	tplData := userEmailVerify{
		Username: username,
		Link:     link,
	}

	subject := "Verify Your Email"
	body, err := createBody(userEmailVerifyTmpl, tplData)
	if err != nil {
		return err
	}

	return p.mail.SendTo(subject, body, []string{email})
}

// emailUserKeyUpdate emails the link with the verification token used for
// setting a new key pair if the email server is set up.
func (p *LegacyPoliteiawww) emailUserKeyUpdate(username, publicKey, token string, recipient map[uuid.UUID]string) error {
	link, err := p.createEmailLink(www.RouteVerifyUpdateUserKey, "", token, "")
	if err != nil {
		return err
	}

	tplData := userKeyUpdate{
		PublicKey: publicKey,
		Username:  username,
		Link:      link,
	}

	subject := "Verify Your New Identity"
	body, err := createBody(userKeyUpdateTmpl, tplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, recipient)
}

// emailUserPasswordReset emails the link with the reset password verification
// token to the provided email address.
func (p *LegacyPoliteiawww) emailUserPasswordReset(username, token string, recipient map[uuid.UUID]string) error {
	// Setup URL
	u, err := url.Parse(p.cfg.WebServerAddress + www.RouteResetPassword)
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("verificationtoken", token)
	q.Set("username", username)
	u.RawQuery = q.Encode()

	// Setup email
	subject := "Reset Your Password"
	tplData := userPasswordReset{
		Link: u.String(),
	}
	body, err := createBody(userPasswordResetTmpl, tplData)
	if err != nil {
		return err
	}

	// Send email
	return p.mail.SendToUsers(subject, body, recipient)
}

// emailUserAccountLocked notifies the user its account has been locked and
// emails the link with the reset password verification token if the email
// server is set up.
func (p *LegacyPoliteiawww) emailUserAccountLocked(username string, recipient map[uuid.UUID]string) error {
	var email string
	for _, e := range recipient {
		email = e
	}
	link, err := p.createEmailLink(ResetPasswordGuiRoute,
		email, "", "")
	if err != nil {
		return err
	}

	tplData := userAccountLocked{
		Link:     link,
		Username: username,
	}

	subject := "Locked Account - Reset Your Password"
	body, err := createBody(userAccountLockedTmpl, tplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, recipient)
}

// emailUserPasswordChanged notifies the user that his password was changed,
// and verifies if he was the author of this action, for security purposes.
func (p *LegacyPoliteiawww) emailUserPasswordChanged(username string, recipient map[uuid.UUID]string) error {
	tplData := userPasswordChanged{
		Username: username,
	}

	subject := "Password Changed - Security Notification"
	body, err := createBody(userPasswordChangedTmpl, tplData)
	if err != nil {
		return err
	}

	return p.mail.SendToUsers(subject, body, recipient)
}

// hashPassword hashes the given password string with the default bcrypt cost
// or the minimum cost if the test flag is set to speed up running tests.
func (p *LegacyPoliteiawww) hashPassword(password string) ([]byte, error) {
	if p.test {
		return bcrypt.GenerateFromPassword([]byte(password),
			bcrypt.MinCost)
	}
	return bcrypt.GenerateFromPassword([]byte(password),
		bcrypt.DefaultCost)
}

// createUsernameRegex generates a regex based on the policy supplied valid
// characters in a user name.
func createUsernameRegex() string {
	var buf bytes.Buffer
	buf.WriteString("^[")

	for _, supportedChar := range www.PolicyUsernameSupportedChars {
		if len(supportedChar) > 1 {
			buf.WriteString(supportedChar)
		} else {
			buf.WriteString(`\` + supportedChar)
		}
	}
	buf.WriteString("]{")
	buf.WriteString(strconv.Itoa(www.PolicyMinUsernameLength) + ",")
	buf.WriteString(strconv.Itoa(www.PolicyMaxUsernameLength) + "}$")

	return buf.String()
}

// validatePubKey verifies that the provided public key is a valid ed25519
// public key.
func validatePubKey(publicKey string) error {
	pk, err := hex.DecodeString(publicKey)
	if err != nil {
		log.Debugf("validatePubKey: decode hex string "+
			"failed for '%v': %v", publicKey, err)
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidPublicKey,
		}
	}

	var emptyPK [identity.PublicKeySize]byte
	switch {
	case len(pk) != len(emptyPK):
		log.Debugf("validatePubKey: invalid size: %v",
			publicKey)
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidPublicKey,
		}
	case bytes.Equal(pk, emptyPK[:]):
		log.Debugf("validatePubKey: key is empty: %v",
			publicKey)
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidPublicKey,
		}
	}

	return nil
}

// validateSignature validates an incoming signature against the specified
// public key and message. This function assumes the provided public key is
// valid.
func validateSignature(pubKey string, signature string, elements ...string) error {
	sig, err := util.ConvertSignature(signature)
	if err != nil {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}
	b, err := hex.DecodeString(pubKey)
	if err != nil {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidPublicKey,
		}
	}
	pk, err := identity.PublicIdentityFromBytes(b)
	if err != nil {
		return err
	}
	var msg string
	for _, v := range elements {
		msg += v
	}
	if !pk.VerifyMessage([]byte(msg), sig) {
		return www.UserError{
			ErrorCode: www.ErrorStatusInvalidSignature,
		}
	}
	return nil
}

// formatUsername normalizes a username to lowercase without leading and
// trailing spaces.
func formatUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

// validateUsername verifies that a username adheres to required policy.
func validateUsername(username string) error {
	if username != formatUsername(username) {
		log.Tracef("validateUsername: not normalized: %s %s",
			username, formatUsername(username))
		return www.UserError{
			ErrorCode: www.ErrorStatusMalformedUsername,
		}
	}
	if len(username) < www.PolicyMinUsernameLength ||
		len(username) > www.PolicyMaxUsernameLength {
		log.Tracef("validateUsername: not within bounds: %s",
			username)
		return www.UserError{
			ErrorCode: www.ErrorStatusMalformedUsername,
		}
	}
	if !validUsername.MatchString(username) {
		log.Tracef("validateUsername: not valid: %s %s",
			username, validUsername.String())
		return www.UserError{
			ErrorCode: www.ErrorStatusMalformedUsername,
		}
	}
	return nil
}

// validatePassword verifies that a password adheres to required policy.
func validatePassword(password string) error {
	if len(password) < www.PolicyMinPasswordLength {
		return www.UserError{
			ErrorCode: www.ErrorStatusMalformedPassword,
		}
	}

	return nil
}

// userIsLocked returns whether the user's account has been locked due to
// failed login attempts.
func userIsLocked(failedLoginAttempts uint64) bool {
	return failedLoginAttempts >= LoginAttemptsToLockUser
}

// newVerificationTokenAndExpiry returns a byte slice of random data that is
// the size of a verification token and a UNIX timestamp that represents the
// expiration of the token.
func newVerificationTokenAndExpiry() ([]byte, int64, error) {
	tokenb, err := util.Random(www.VerificationTokenSize)
	if err != nil {
		return nil, 0, err
	}
	d := time.Duration(www.VerificationExpiryHours) * time.Hour
	expiry := time.Now().Add(d).Unix()
	return tokenb, expiry, nil
}
