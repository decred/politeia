// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"sort"
	"time"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	www "github.com/decred/politeia/politeiawww/api/www/v1"
	"github.com/decred/politeia/politeiawww/user"
	"github.com/google/uuid"
)

// cmsUsersByDomain returns all cms user within the provided contractor domain.
func (p *LegacyPoliteiawww) cmsUsersByDomain(d cms.DomainTypeT) ([]user.CMSUser, error) {
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

func (p *LegacyPoliteiawww) processEditCMSUser(ecu cms.EditUser, u *user.User) (*cms.EditUserReply, error) {
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

func (p *LegacyPoliteiawww) processManageCMSUser(mu cms.CMSManageUser) (*cms.CMSManageUserReply, error) {
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

func (p *LegacyPoliteiawww) processCMSUserDetails(ud *cms.UserDetails, isCurrentUser bool, isAdmin bool) (*cms.UserDetailsReply, error) {
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
func (p *LegacyPoliteiawww) getCMSUserByID(id string) (*cms.User, error) {
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

func (p *LegacyPoliteiawww) getCMSUserByIDRaw(id string) (*user.CMSUser, error) {
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

func (p *LegacyPoliteiawww) getCMSUserWeights() (map[string]int64, error) {
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
func (p *LegacyPoliteiawww) issuanceDCCUser(userid, sponsorUserID string, domain, contractorType int) error {
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

func (p *LegacyPoliteiawww) revokeDCCUser(userid string) error {
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

func (p *LegacyPoliteiawww) processUserSubContractors(u *user.User) (*cms.UserSubContractorsReply, error) {
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

// processProposalOwner returns a list of cms users given a proposal token.
// If the user is set to have ownership of this proposal then they will be
// added to the list.
func (p *LegacyPoliteiawww) processProposalOwner(po cms.ProposalOwner) (*cms.ProposalOwnerReply, error) {
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
