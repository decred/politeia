package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
)

// cmsUsersByDomain returns all cms user within the provided contractor domain.
func (p *politeiawww) cmsUsersByDomain(d cms.DomainTypeT) ([]user.CMSUser, error) {
	// Setup plugin command
	cu := user.CMSUsersByDomain{
		Domain: int(d),
	}
	payload, err := user.EncodeCMSUsersByDomain(cu)
	if err != nil {
		return nil, err
	}
	pc := user.PluginCommand{
		ID:      user.CMSPluginID,
		Command: user.CmdCMSUsersByDomain,
		Payload: string(payload),
	}

	// Execute plugin command
	pcr, err := p.db.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	// Decode reply
	reply, err := user.DecodeCMSUsersByDomainReply([]byte(pcr.Payload))
	if err != nil {
		return nil, err
	}

	return reply.Users, nil
}

// processInviteNewUser creates a new user in the db if it doesn't already
// exist and sets a verification token and expiry; the token must be
// verified before it expires. If the user already exists in the db
// and its token is expired, it generates a new one.
//
// Note that this function always returns a InviteNewUserReply. The caller
// shall verify error and determine how to return this information upstream.
func (p *politeiawww) processInviteNewUser(u cms.InviteNewUser) (*www.NewUserReply, error) {
	log.Tracef("processInviteNewUser: %v", u.Email)

	// Validate email
	if !validEmail.MatchString(u.Email) {
		log.Debugf("processInviteNewUser: invalid email '%v'", u.Email)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusMalformedEmail,
		}
	}

	// Check if the user is already verified.
	existingUser, err := p.userByEmail(u.Email)
	if err == nil {
		if existingUser.NewUserVerificationToken == nil {
			return &www.NewUserReply{}, nil
		}
	}

	// Generate the verification token and expiry.
	token, expiry, err := newVerificationTokenAndExpiry()
	if err != nil {
		return nil, err
	}

	// Try to email the verification link first; if it fails, then
	// the new user won't be created.
	//
	// This is conditional on the email server being setup.
	err = p.emailInviteNewUserVerificationLink(u.Email,
		hex.EncodeToString(token))
	if err != nil {
		log.Errorf("processInviteNewUser: verification email "+
			"failed for '%v': %v", u.Email, err)
		return &www.NewUserReply{}, nil
	}

	// If the user already exists, the user record is updated
	// in the db in order to reset the verification token and
	// expiry.
	if existingUser != nil {
		existingUser.NewUserVerificationToken = token
		existingUser.NewUserVerificationExpiry = expiry
		err = p.db.UserUpdate(*existingUser)
		if err != nil {
			return nil, err
		}

		return &www.NewUserReply{
			VerificationToken: hex.EncodeToString(token),
		}, nil
	}

	// Create a new cms user with the provided information.
	// This temporarily sets the username to the given email, which will be
	// overwritten during registration. This is needed since the constraints
	// on cockroachdb for usernames requires there to be no duplicates. If
	// unset, the username of "" will cause a duplicate error to be thrown.
	nu := user.NewCMSUser{
		Email:                     strings.ToLower(u.Email),
		Username:                  strings.ToLower(u.Email),
		NewUserVerificationToken:  token,
		NewUserVerificationExpiry: expiry,
	}
	payload, err := user.EncodeNewCMSUser(nu)
	if err != nil {
		return nil, err
	}
	pc := user.PluginCommand{
		ID:      user.CMSPluginID,
		Command: user.CmdNewCMSUser,
		Payload: string(payload),
	}
	_, err = p.db.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	// Update user emails cache
	usr, err := p.db.UserGetByUsername(nu.Username)
	if err != nil {
		return nil, err
	}
	p.setUserEmailsCache(usr.Email, usr.ID)

	return &www.NewUserReply{
		VerificationToken: hex.EncodeToString(token),
	}, nil
}

// processRegisterUser allows a CMS user that has received an invite to
// register their account. The username and password for the account are
// updated and the user's email address and identity are marked as verified.
func (p *politeiawww) processRegisterUser(u cms.RegisterUser) (*cms.RegisterUserReply, error) {
	log.Tracef("processRegisterUser: %v", u.Email)
	var reply cms.RegisterUserReply

	// Check that the user already exists.
	existingUser, err := p.userByEmail(u.Email)
	if err != nil {
		if err == user.ErrUserNotFound {
			log.Debugf("RegisterUser failure for %v: user not found",
				u.Email)
			return nil, www.UserError{
				ErrorCode: www.ErrorStatusVerificationTokenInvalid,
			}
		}
		return nil, err
	}

	// Validate public key and ensure its unique.
	err = validatePubKey(u.PublicKey)
	if err != nil {
		return nil, err
	}
	_, err = p.db.UserGetByPubKey(u.PublicKey)
	switch err {
	case user.ErrUserNotFound:
		// Pubkey is unique; continue
	case nil:
		// Pubkey is not unique
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusDuplicatePublicKey,
		}
	default:
		// All other errors
		return nil, err
	}

	// Format and validate the username.
	username := formatUsername(u.Username)
	err = validateUsername(username)
	if err != nil {
		return nil, err
	}

	// Ensure username is unique.
	_, err = p.db.UserGetByUsername(u.Username)
	switch err {
	case nil:
		// Duplicate username
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusDuplicateUsername,
		}
	case user.ErrUserNotFound:
		// Username doesn't exist; continue
	default:
		return nil, err
	}

	// Validate the password.
	err = validatePassword(u.Password)
	if err != nil {
		return nil, err
	}

	// Hash the user's password.
	hashedPassword, err := p.hashPassword(u.Password)
	if err != nil {
		return nil, err
	}

	// Decode the verification token.
	token, err := hex.DecodeString(u.VerificationToken)
	if err != nil {
		log.Debugf("Register failure for %v: verification token could "+
			"not be decoded: %v", u.Email, err)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the verification token matches.
	if !bytes.Equal(token, existingUser.NewUserVerificationToken) {
		log.Debugf("Register failure for %v: verification token doesn't "+
			"match, expected %v", u.Email, existingUser.NewUserVerificationToken)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenInvalid,
		}
	}

	// Check that the token hasn't expired.
	if time.Now().Unix() > existingUser.NewUserVerificationExpiry {
		log.Debugf("Register failure for %v: verification token expired",
			u.Email)
		return nil, www.UserError{
			ErrorCode: www.ErrorStatusVerificationTokenExpired,
		}
	}

	// Create a new database user with the provided information.
	newUser := user.User{
		ID:             existingUser.ID,
		Email:          strings.ToLower(u.Email),
		Username:       username,
		HashedPassword: hashedPassword,
	}

	// Setup newUser's identity with the provided public key. An
	// additional verification step to activate the identity is
	// not needed since the registration email already serves as
	// the verification.
	id, err := user.NewIdentity(u.PublicKey)
	if err != nil {
		return nil, err
	}
	err = newUser.AddIdentity(*id)
	if err != nil {
		return nil, err
	}
	err = newUser.ActivateIdentity(id.Key[:])
	if err != nil {
		return nil, err
	}

	// Update the user in the db.
	err = p.db.UserUpdate(newUser)
	if err != nil {
		return nil, err
	}

	// Even if user is non-nil, this will bring it up-to-date
	// with the new information inserted via newUser.
	existingUser, err = p.userByEmail(newUser.Email)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve account info for %v: %v",
			newUser.Email, err)
	}

	err = p.db.UserUpdate(newUser)
	if err != nil {
		return nil, err
	}
	return &reply, nil
}
