// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package legacy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
)

// processInviteNewUser creates a new user in the db if it doesn't already
// exist and sets a verification token and expiry; the token must be
// verified before it expires. If the user already exists in the db
// and its token is expired, it generates a new one.
//
// Note that this function always returns a InviteNewUserReply. The caller
// shall verify error and determine how to return this information upstream.
func (p *LegacyPoliteiawww) processInviteNewUser(u cms.InviteNewUser) (*cms.InviteNewUserReply, error) {
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
			return &cms.InviteNewUserReply{}, nil
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
	err = p.emailUserCMSInvite(u.Email, hex.EncodeToString(token))
	if err != nil {
		log.Errorf("processInviteNewUser: verification email "+
			"failed for '%v': %v", u.Email, err)
		return &cms.InviteNewUserReply{}, nil
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

		return &cms.InviteNewUserReply{
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

	// Set the user to temporary if request includes it.
	// While this will allow a user to bypass the DCC process, the temporary
	// users will have extensive restrictions on their account and ability
	// to submit invoices.
	if u.Temporary {
		nu.ContractorType = int(cms.ContractorTypeTemp)
	} else {
		nu.ContractorType = int(cms.ContractorTypeNominee)
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

	return &cms.InviteNewUserReply{
		VerificationToken: hex.EncodeToString(token),
	}, nil
}

// processRegisterUser allows a CMS user that has received an invite to
// register their account. The username and password for the account are
// updated and the user's email address and identity are marked as verified.
func (p *LegacyPoliteiawww) processRegisterUser(u cms.RegisterUser) (*cms.RegisterUserReply, error) {
	log.Tracef("processRegisterUser: %v", u.Email)
	var reply cms.RegisterUserReply

	// Check that the user already exists.
	existingUser, err := p.userByEmail(u.Email)
	if err != nil {
		if errors.Is(err, user.ErrUserNotFound) {
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
		ID:                        existingUser.ID,
		Email:                     strings.ToLower(u.Email),
		Username:                  username,
		HashedPassword:            hashedPassword,
		NewUserVerificationToken:  nil,
		NewUserVerificationExpiry: 0,
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

// processCMSUsers returns a list of cms users given a set of filters. If
// either domain or contractor is non-zero then they are used as matching
// criteria, otherwise the full list will be returned.
func (p *LegacyPoliteiawww) processCMSUsers(users *cms.CMSUsers) (*cms.CMSUsersReply, error) {
	log.Tracef("processCMSUsers")

	domain := int(users.Domain)
	contractortype := int(users.ContractorType)

	matchedUsers := make([]cms.AbridgedCMSUser, 0, www.UserListPageSize)

	if domain != 0 {
		// Setup plugin command
		cu := user.CMSUsersByDomain{
			Domain: domain,
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
		for _, u := range reply.Users {
			// Only add matched users if contractor type is 0  or it matches
			// the request
			if contractortype == 0 ||
				(contractortype != 0 && u.ContractorType == contractortype) {
				matchedUsers = append(matchedUsers, cms.AbridgedCMSUser{
					Domain:         cms.DomainTypeT(u.Domain),
					Username:       u.Username,
					ContractorType: cms.ContractorTypeT(u.ContractorType),
					ID:             u.ID.String(),
				})
			}
		}
	} else if contractortype != 0 {
		// Setup plugin command
		cu := user.CMSUsersByContractorType{
			ContractorType: contractortype,
		}
		payload, err := user.EncodeCMSUsersByContractorType(cu)
		if err != nil {
			return nil, err
		}
		pc := user.PluginCommand{
			ID:      user.CMSPluginID,
			Command: user.CmdCMSUsersByContractorType,
			Payload: string(payload),
		}

		// Execute plugin command
		pcr, err := p.db.PluginExec(pc)
		if err != nil {
			return nil, err
		}

		// Decode reply
		reply, err := user.DecodeCMSUsersByContractorTypeReply(
			[]byte(pcr.Payload))
		if err != nil {
			return nil, err
		}
		for _, u := range reply.Users {
			// We already know domain is 0 if here so no need to check.
			matchedUsers = append(matchedUsers, cms.AbridgedCMSUser{
				Domain:         cms.DomainTypeT(u.Domain),
				Username:       u.Username,
				ContractorType: cms.ContractorTypeT(u.ContractorType),
				ID:             u.ID.String(),
			})
		}
	} else {
		// Both contractor type and domain are 0 so just return all users.
		err := p.db.AllUsers(func(u *user.User) {
			// Setup plugin command
			cu := user.CMSUserByID{
				ID: u.ID.String(),
			}
			payload, err := user.EncodeCMSUserByID(cu)
			if err != nil {
				log.Error(err)
				return
			}
			pc := user.PluginCommand{
				ID:      user.CMSPluginID,
				Command: user.CmdCMSUserByID,
				Payload: string(payload),
			}

			// Execute plugin command
			pcr, err := p.db.PluginExec(pc)
			if err != nil {
				log.Error(err)
				return
			}

			// Decode reply
			reply, err := user.DecodeCMSUserByIDReply([]byte(pcr.Payload))
			if err != nil {
				log.Error(err)
				return
			}
			matchedUsers = append(matchedUsers, cms.AbridgedCMSUser{
				ID:             u.ID.String(),
				Username:       u.Username,
				Domain:         cms.DomainTypeT(reply.User.Domain),
				ContractorType: cms.ContractorTypeT(reply.User.ContractorType),
			})
		})
		if err != nil {
			return nil, err
		}
	}

	// Sort results alphabetically.
	sort.Slice(matchedUsers, func(i, j int) bool {
		return matchedUsers[i].Username < matchedUsers[j].Username
	})

	return &cms.CMSUsersReply{
		Users: matchedUsers,
	}, nil
}
