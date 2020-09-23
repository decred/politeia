// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
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
func (p *politeiawww) processInviteNewUser(u cms.InviteNewUser) (*cms.InviteNewUserReply, error) {
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

func (p *politeiawww) processEditCMSUser(ecu cms.EditUser, u *user.User) (*cms.EditUserReply, error) {
	log.Tracef("processEditCMSUser: %v", u.Email)

	reply := cms.EditUserReply{}

	err := validateUserInformation(ecu)
	if err != nil {
		return nil, err
	}

	uu := user.UpdateCMSUser{
		ID: u.ID,
	}

	if ecu.GitHubName != "" {
		uu.GitHubName = ecu.GitHubName
	}
	if ecu.MatrixName != "" {
		uu.MatrixName = ecu.MatrixName
	}
	if ecu.ContractorName != "" {
		uu.ContractorName = ecu.ContractorName
	}
	if ecu.ContractorLocation != "" {
		uu.ContractorLocation = ecu.ContractorLocation
	}
	if ecu.ContractorContact != "" {
		uu.ContractorContact = ecu.ContractorContact
	}
	payload, err := user.EncodeUpdateCMSUser(uu)
	if err != nil {
		return nil, err
	}
	pc := user.PluginCommand{
		ID:      user.CMSPluginID,
		Command: user.CmdUpdateCMSUser,
		Payload: string(payload),
	}
	_, err = p.db.PluginExec(pc)
	if err != nil {
		return nil, err
	}
	return &reply, nil
}

func (p *politeiawww) processManageCMSUser(mu cms.CMSManageUser) (*cms.CMSManageUserReply, error) {
	log.Tracef("processManageCMSUser: %v", mu.UserID)

	editUser, err := p.userByIDStr(mu.UserID)
	if err != nil {
		return nil, err
	}

	uu := user.UpdateCMSUser{
		ID: editUser.ID,
	}

	if mu.Domain != 0 {
		uu.Domain = int(mu.Domain)
	}
	if mu.ContractorType != 0 {
		uu.ContractorType = int(mu.ContractorType)
	}
	if len(mu.SupervisorUserIDs) > 0 {
		// Validate SupervisorUserID input
		parseSuperUserIds := make([]uuid.UUID, 0, len(mu.SupervisorUserIDs))
		for _, super := range mu.SupervisorUserIDs {
			parseUUID, err := uuid.Parse(super)
			if err != nil {
				e := fmt.Sprintf("invalid uuid: %v", super)
				return nil, www.UserError{
					ErrorCode:    cms.ErrorStatusInvalidSupervisorUser,
					ErrorContext: []string{e},
				}
			}
			u, err := p.getCMSUserByID(super)
			if err != nil {
				e := fmt.Sprintf("user not found: %v", super)
				return nil, www.UserError{
					ErrorCode:    cms.ErrorStatusInvalidSupervisorUser,
					ErrorContext: []string{e},
				}
			}
			if u.ContractorType != cms.ContractorTypeSupervisor {
				e := fmt.Sprintf("user not a supervisor: %v", super)
				return nil, www.UserError{
					ErrorCode:    cms.ErrorStatusInvalidSupervisorUser,
					ErrorContext: []string{e},
				}
			}
			parseSuperUserIds = append(parseSuperUserIds, parseUUID)
		}
		uu.SupervisorUserIDs = parseSuperUserIds
	}

	if len(mu.ProposalsOwned) > 0 {
		uu.ProposalsOwned = mu.ProposalsOwned
	}

	payload, err := user.EncodeUpdateCMSUser(uu)
	if err != nil {
		return nil, err
	}
	pc := user.PluginCommand{
		ID:      user.CMSPluginID,
		Command: user.CmdUpdateCMSUser,
		Payload: string(payload),
	}
	_, err = p.db.PluginExec(pc)
	if err != nil {
		return nil, err
	}
	return &cms.CMSManageUserReply{}, nil
}

// filterCMSUserPublicFields creates a filtered copy of a cms User that only
// contains public information.
func filterCMSUserPublicFields(user cms.User) cms.User {
	return cms.User{
		ID:         user.ID,
		Admin:      user.Admin,
		Username:   user.Username,
		Identities: user.Identities,

		// CMS User Details
		ContractorType: user.ContractorType,
		GitHubName:     user.GitHubName,
		MatrixName:     user.MatrixName,
		Domain:         user.Domain,
	}
}

func (p *politeiawww) processCMSUserDetails(ud *cms.UserDetails, isCurrentUser bool, isAdmin bool) (*cms.UserDetailsReply, error) {
	reply := cms.UserDetailsReply{}
	u, err := p.getCMSUserByID(ud.UserID)
	if err != nil {
		return nil, err
	}

	// Filter returned fields in case the user isn't the admin or the current user
	if !isAdmin && !isCurrentUser {
		reply.User = filterCMSUserPublicFields(*u)
	} else {
		reply.User = *u
	}

	return &reply, nil
}

func validateUserInformation(userInfo cms.EditUser) error {
	var err error
	if userInfo.GitHubName != "" {
		contact := formatContact(userInfo.GitHubName)
		err = validateContact(contact)
		if err != nil {
			return www.UserError{
				ErrorCode: cms.ErrorStatusInvoiceMalformedContact,
			}
		}
	}
	if userInfo.MatrixName != "" {
		contact := formatContact(userInfo.MatrixName)
		err = validateContact(contact)
		if err != nil {
			return www.UserError{
				ErrorCode: cms.ErrorStatusInvoiceMalformedContact,
			}
		}
	}
	if userInfo.ContractorName != "" {
		name := formatName(userInfo.ContractorName)
		err = validateName(name)
		if err != nil {
			return www.UserError{
				ErrorCode: cms.ErrorStatusMalformedName,
			}
		}
	}
	if userInfo.ContractorLocation != "" {
		location := formatLocation(userInfo.ContractorLocation)
		err = validateLocation(location)
		if err != nil {
			return www.UserError{
				ErrorCode: cms.ErrorStatusMalformedLocation,
			}
		}
	}
	if userInfo.ContractorContact != "" {
		contact := formatContact(userInfo.ContractorContact)
		err = validateContact(contact)
		if err != nil {
			return www.UserError{
				ErrorCode: cms.ErrorStatusInvoiceMalformedContact,
			}
		}
	}
	return nil
}
func (p *politeiawww) getCMSUserByID(id string) (*cms.User, error) {
	ubi := user.CMSUserByID{
		ID: id,
	}
	payload, err := user.EncodeCMSUserByID(ubi)
	if err != nil {
		return nil, err
	}
	pc := user.PluginCommand{
		ID:      user.CMSPluginID,
		Command: user.CmdCMSUserByID,
		Payload: string(payload),
	}
	payloadReply, err := p.db.PluginExec(pc)
	if err != nil {
		return nil, err
	}
	ubir, err := user.DecodeCMSUserByIDReply([]byte(payloadReply.Payload))
	if err != nil {
		return nil, err
	}
	u := convertCMSUserFromDatabaseUser(ubir.User)
	return &u, nil
}

func (p *politeiawww) getCMSUserByIDRaw(id string) (*user.CMSUser, error) {
	ubi := user.CMSUserByID{
		ID: id,
	}
	payload, err := user.EncodeCMSUserByID(ubi)
	if err != nil {
		return nil, err
	}
	pc := user.PluginCommand{
		ID:      user.CMSPluginID,
		Command: user.CmdCMSUserByID,
		Payload: string(payload),
	}
	payloadReply, err := p.db.PluginExec(pc)
	if err != nil {
		return nil, err
	}
	ubir, err := user.DecodeCMSUserByIDReply([]byte(payloadReply.Payload))
	if err != nil {
		return nil, err
	}
	return ubir.User, nil
}

func (p *politeiawww) getCMSUserWeights() (map[string]int64, error) {
	userWeights := make(map[string]int64, 1080)

	/*
		1) Determine most recent payout month
		2) For each user
		   1) Look back for 6 months of invoices (that were paid out)
		   2) Add up all minutes billed over that time period.
		   3) Set user weight as total number of billed minutes.
	*/

	weightEnd := time.Now()
	weightMonthEnd := uint(weightEnd.Month())
	weightYearEnd := uint(weightEnd.Year())

	weightStart := time.Now().AddDate(0, -1*userWeightMonthLookback, 0)
	weightMonthStart := uint(weightStart.Month())
	weightYearStart := uint(weightStart.Year())

	// Subtract one nano second from start date and add one to end date to avoid having equal times.
	startDate := time.Date(int(weightYearStart), time.Month(weightMonthStart), 0, 0, 0, 0, -1, time.UTC)
	endDate := time.Date(int(weightYearEnd), time.Month(weightMonthEnd), 0, 0, 0, 0, 1, time.UTC)

	err := p.db.AllUsers(func(user *user.User) {
		cmsUser, err := p.getCMSUserByID(user.ID.String())
		if err != nil {
			log.Errorf("getCMSUserWeights: getCMSUserByID %v %v",
				user.ID.String(), err)
			return
		}

		if cmsUser.ContractorType != cms.ContractorTypeDirect &&
			cmsUser.ContractorType != cms.ContractorTypeSubContractor &&
			cmsUser.ContractorType != cms.ContractorTypeSupervisor {
			return
		}

		var billedMinutes int64
		// Calculate sub contractor weight here
		if cmsUser.ContractorType == cms.ContractorTypeSubContractor {
			for _, superID := range cmsUser.SupervisorUserIDs {
				superUser, err := p.getCMSUserByID(superID)
				if err != nil {
					log.Errorf("getCMSUserWeights: getCMSUserByID %v %v",
						superID, err)
					return
				}
				superInvoices, err := p.cmsDB.InvoicesByUserID(superUser.ID)
				if err != nil {
					log.Errorf("getCMSUserWeights: InvoicesByUserID %v", err)
				}
				for _, i := range superInvoices {
					invoiceDate := time.Date(int(i.Year), time.Month(i.Month), 0, 0, 0, 0, 0, time.UTC)
					if invoiceDate.After(startDate) && endDate.After(invoiceDate) {
						for _, li := range i.LineItems {
							// Only take into account billed minutes if the line
							// item matches their userID
							if li.Type == cms.LineItemTypeSubHours &&
								li.SubUserID == user.ID.String() {
								billedMinutes += int64(li.Labor)
							}
						}
					}
				}
			}
		} else {
			userInvoices, err := p.cmsDB.InvoicesByUserID(cmsUser.ID)
			if err != nil {
				log.Errorf("getCMSUserWeights: InvoicesByUserID %v", err)
				return
			}
			for _, i := range userInvoices {
				invoiceDate := time.Date(int(i.Year), time.Month(i.Month), 0, 0, 0, 0, 0, time.UTC)
				if invoiceDate.After(startDate) && endDate.After(invoiceDate) {
					// now look at the lineitems within that invoice and
					// tabulate billed hours
					for _, li := range i.LineItems {
						billedMinutes += int64(li.Labor)
					}
				}
			}
		}
		userWeights[cmsUser.ID] = billedMinutes
	})
	if err != nil {
		return nil, err
	}

	return userWeights, nil

}

// convertCMSUserFromDatabaseUser converts a user User to a cms User.
func convertCMSUserFromDatabaseUser(user *user.CMSUser) cms.User {
	superUserIDs := make([]string, 0, len(user.SupervisorUserIDs))
	for _, userIDs := range user.SupervisorUserIDs {
		superUserIDs = append(superUserIDs, userIDs.String())
	}
	return cms.User{
		ID:                              user.User.ID.String(),
		Admin:                           user.User.Admin,
		Email:                           user.User.Email,
		Username:                        user.User.Username,
		NewUserVerificationToken:        user.User.NewUserVerificationToken,
		NewUserVerificationExpiry:       user.User.NewUserVerificationExpiry,
		UpdateKeyVerificationToken:      user.User.UpdateKeyVerificationToken,
		UpdateKeyVerificationExpiry:     user.User.UpdateKeyVerificationExpiry,
		ResetPasswordVerificationToken:  user.User.ResetPasswordVerificationToken,
		ResetPasswordVerificationExpiry: user.User.ResetPasswordVerificationExpiry,
		LastLoginTime:                   user.User.LastLoginTime,
		FailedLoginAttempts:             user.User.FailedLoginAttempts,
		Deactivated:                     user.User.Deactivated,
		Locked:                          userIsLocked(user.User.FailedLoginAttempts),
		Identities:                      convertWWWIdentitiesFromDatabaseIdentities(user.User.Identities),
		EmailNotifications:              user.User.EmailNotifications,
		Domain:                          cms.DomainTypeT(user.Domain),
		ContractorType:                  cms.ContractorTypeT(user.ContractorType),
		ContractorName:                  user.ContractorName,
		ContractorLocation:              user.ContractorLocation,
		ContractorContact:               user.ContractorContact,
		MatrixName:                      user.MatrixName,
		GitHubName:                      user.GitHubName,
		SupervisorUserIDs:               superUserIDs,
		ProposalsOwned:                  user.ProposalsOwned,
	}
}

// issuanceDCCUser does the processing to move a nominated user to a fully
// approved and invite them onto CMS.
func (p *politeiawww) issuanceDCCUser(userid, sponsorUserID string, domain, contractorType int) error {
	nominatedUser, err := p.userByIDStr(userid)
	if err != nil {
		return err
	}

	if nominatedUser == nil {
		return err
	}

	nomineeUserID, err := uuid.Parse(userid)
	if err != nil {
		return err
	}
	uu := user.UpdateCMSUser{
		ID:             nomineeUserID,
		ContractorType: contractorType,
		Domain:         domain,
	}

	// If the nominee was an approved Subcontractor, then use the sponsor user
	// ID as the SupervisorUserID
	superVisorUserIDs := make([]uuid.UUID, 1)
	if contractorType == int(cms.ContractorTypeSubContractor) {
		parsed, err := uuid.Parse(sponsorUserID)
		if err != nil {
			return err
		}
		superVisorUserIDs[0] = parsed
		uu.SupervisorUserIDs = superVisorUserIDs
	}

	payload, err := user.EncodeUpdateCMSUser(uu)
	if err != nil {
		return err
	}
	pc := user.PluginCommand{
		ID:      user.CMSPluginID,
		Command: user.CmdUpdateCMSUser,
		Payload: string(payload),
	}
	_, err = p.db.PluginExec(pc)
	if err != nil {
		return err
	}

	// Try to email the verification link first; if it fails, then
	// the new user won't be created.
	//
	// This is conditional on the email server being setup.
	err = p.emailUserDCCApproved(nominatedUser.Email)
	if err != nil {
		log.Errorf("processApproveDCC: verification email "+
			"failed for '%v': %v", nominatedUser.Email, err)
		return err
	}

	return nil
}

func (p *politeiawww) revokeDCCUser(userid string) error {
	// Do full userdb update and reject user creds
	nomineeUserID, err := uuid.Parse(userid)
	if err != nil {
		return err
	}
	uu := user.UpdateCMSUser{
		ID:             nomineeUserID,
		ContractorType: int(cms.ContractorTypeRevoked),
	}
	payload, err := user.EncodeUpdateCMSUser(uu)
	if err != nil {
		return err
	}
	pc := user.PluginCommand{
		ID:      user.CMSPluginID,
		Command: user.CmdUpdateCMSUser,
		Payload: string(payload),
	}
	_, err = p.db.PluginExec(pc)
	if err != nil {
		return err
	}
	return nil
}

func (p *politeiawww) processUserSubContractors(u *user.User) (*cms.UserSubContractorsReply, error) {
	usc := user.CMSUserSubContractors{
		ID: u.ID.String(),
	}
	payload, err := user.EncodeCMSUserSubContractors(usc)
	if err != nil {
		return nil, err
	}
	pc := user.PluginCommand{
		ID:      user.CMSPluginID,
		Command: user.CmdCMSUserSubContractors,
		Payload: string(payload),
	}
	payloadReply, err := p.db.PluginExec(pc)
	if err != nil {
		return nil, err
	}
	cmsUsers, err := user.DecodeCMSUserSubContractorsReply([]byte(payloadReply.Payload))
	if err != nil {
		return nil, err
	}
	convertedCMSUsers := make([]cms.User, 0, len(cmsUsers.Users))
	for _, uu := range cmsUsers.Users {
		converted := convertCMSUserFromDatabaseUser(&uu)
		convertedCMSUsers = append(convertedCMSUsers, converted)
	}
	uscr := &cms.UserSubContractorsReply{
		Users: convertedCMSUsers,
	}
	return uscr, nil
}

// processCMSUsers returns a list of cms users given a set of filters. If
// either domain or contractor is non-zero then they are used as matching
// criteria, otherwise the full list will be returned.
func (p *politeiawww) processCMSUsers(users *cms.CMSUsers) (*cms.CMSUsersReply, error) {
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

// processProposalOwner returns a list of cms users given a proposal token.
// If the user is set to have ownership of this proposal then they will be
// added to the list.
func (p *politeiawww) processProposalOwner(po cms.ProposalOwner) (*cms.ProposalOwnerReply, error) {
	log.Tracef("processProposalOwner")

	// Setup plugin command
	cupt := user.CMSUsersByProposalToken{
		Token: po.ProposalToken,
	}
	payload, err := user.EncodeCMSUsersByProposalToken(cupt)
	if err != nil {
		return nil, err
	}
	pc := user.PluginCommand{
		ID:      user.CMSPluginID,
		Command: user.CmdCMSUsersByProposalToken,
		Payload: string(payload),
	}

	// Execute plugin command
	pcr, err := p.db.PluginExec(pc)
	if err != nil {
		return nil, err
	}

	// Decode reply
	reply, err := user.DecodeCMSUsersByProposalTokenReply([]byte(pcr.Payload))
	if err != nil {
		return nil, err
	}

	matchedUsers := make([]cms.AbridgedCMSUser, 0, len(reply.Users))
	for _, u := range reply.Users {
		matchedUsers = append(matchedUsers, cms.AbridgedCMSUser{
			ID:             u.ID.String(),
			Username:       u.Username,
			Domain:         cms.DomainTypeT(u.Domain),
			ContractorType: cms.ContractorTypeT(u.ContractorType),
		})
	}
	// Sort results alphabetically.
	sort.Slice(matchedUsers, func(i, j int) bool {
		return matchedUsers[i].Username < matchedUsers[j].Username
	})

	return &cms.ProposalOwnerReply{
		Users: matchedUsers,
	}, nil
}
