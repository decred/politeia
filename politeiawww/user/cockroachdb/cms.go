package cockroachdb

import (
	"fmt"
	"strings"

	"github.com/thi4go/politeia/politeiawww/user"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
)

const (
	// CMS plugin table names
	tableCMSUsers = "cms_users"
)

func (c *cockroachdb) convertCMSUserFromDatabase(cu CMSUser) (*user.CMSUser, error) {
	proposalsOwned := strings.Split(cu.ProposalsOwned, ",")
	superUserIds := strings.Split(cu.SupervisorUserID, ",")
	parsedUUIds := make([]uuid.UUID, 0, len(superUserIds))
	for _, userIds := range superUserIds {
		if userIds == "" {
			continue
		}
		parsed, err := uuid.Parse(strings.TrimSpace(userIds))
		if err != nil {
			return nil, err
		}
		parsedUUIds = append(parsedUUIds, parsed)
	}
	u := user.CMSUser{
		Domain:             cu.Domain,
		GitHubName:         cu.GitHubName,
		MatrixName:         cu.MatrixName,
		ContractorType:     cu.ContractorType,
		ContractorName:     cu.ContractorName,
		ContractorLocation: cu.ContractorLocation,
		ContractorContact:  cu.ContractorContact,
		SupervisorUserIDs:  parsedUUIds,
		ProposalsOwned:     proposalsOwned,
	}
	b, _, err := c.decrypt(cu.User.Blob)
	if err != nil {
		return nil, err
	}
	usr, err := user.DecodeUser(b)
	if err != nil {
		return nil, err
	}
	u.User = *usr
	return &u, nil
}

func (c *cockroachdb) convertCMSUsersFromDatabase(cu []CMSUser) ([]user.CMSUser, error) {
	users := make([]user.CMSUser, 0, len(cu))
	for _, v := range cu {
		u, err := c.convertCMSUserFromDatabase(v)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
	}
	return users, nil
}

// newCMSUser creates a new User record and a corresponding CMSUser record
// with the provided user info.
//
// This function must be called using a transaction.
func (c *cockroachdb) newCMSUser(tx *gorm.DB, nu user.NewCMSUser) error {
	// Create a new User record
	u := user.User{
		Email:                     nu.Email,
		Username:                  nu.Username,
		NewUserVerificationToken:  nu.NewUserVerificationToken,
		NewUserVerificationExpiry: nu.NewUserVerificationExpiry,
	}
	id, err := c.userNew(tx, u)
	if err != nil {
		return err
	}

	// Create a CMSUser record
	cms := CMSUser{
		ID:             *id,
		ContractorType: nu.ContractorType,
	}
	err = tx.Create(&cms).Error
	if err != nil {
		return err
	}
	return nil
}

// cmdNewCMSUser inserts a new CMSUser record into the database.
func (c *cockroachdb) cmdNewCMSUser(payload string) (string, error) {
	// Decode payload
	nu, err := user.DecodeNewCMSUser([]byte(payload))
	if err != nil {
		return "", err
	}

	// Create a new User record and a new CMSUser
	// record using a transaction.
	tx := c.userDB.Begin()
	err = c.newCMSUser(tx, *nu)
	if err != nil {
		tx.Rollback()
		return "", err
	}
	err = tx.Commit().Error
	if err != nil {
		return "", err
	}

	// Prepare reply
	var nur user.NewCMSUserReply
	reply, err := user.EncodeNewCMSUserReply(nur)
	if err != nil {
		return "", nil
	}

	return string(reply), nil
}

// updateCMSUser updates an existing  CMSUser record with the provided user
// info.
//
// This function must be called using a transaction.
func (c *cockroachdb) updateCMSUser(tx *gorm.DB, nu user.UpdateCMSUser) error {
	cms := CMSUser{
		ID: nu.ID,
	}
	var superVisorUserIds string
	for i, userIds := range nu.SupervisorUserIDs {
		if i == 0 {
			superVisorUserIds = userIds.String()
		} else {
			superVisorUserIds += ", " + userIds.String()
		}
	}
	var proposalsOwned string
	for i, proposal := range nu.ProposalsOwned {
		if i == 0 {
			proposalsOwned = proposal
		} else {
			proposalsOwned += ", " + proposal
		}
	}
	err := tx.First(&cms).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			cms.Domain = nu.Domain
			cms.GitHubName = nu.GitHubName
			cms.MatrixName = nu.MatrixName
			cms.ContractorName = nu.ContractorName
			cms.ContractorType = nu.ContractorType
			cms.ContractorLocation = nu.ContractorLocation
			cms.ContractorContact = nu.ContractorContact
			cms.SupervisorUserID = superVisorUserIds
			cms.ProposalsOwned = proposalsOwned
			err = tx.Create(&cms).Error
			if err != nil {
				return err
			}
			return nil
		}
		return err
	}
	cms.Domain = nu.Domain
	cms.GitHubName = nu.GitHubName
	cms.MatrixName = nu.MatrixName
	cms.ContractorName = nu.ContractorName
	cms.ContractorType = nu.ContractorType
	cms.ContractorLocation = nu.ContractorLocation
	cms.ContractorContact = nu.ContractorContact
	cms.SupervisorUserID = superVisorUserIds
	cms.ProposalsOwned = proposalsOwned

	err = tx.Save(&cms).Error
	if err != nil {
		return err
	}
	return nil
}

// cmdUpdateCMSUser updates an existing CMSUser record in the database.
func (c *cockroachdb) cmdUpdateCMSUser(payload string) (string, error) {
	// Decode payload
	uu, err := user.DecodeUpdateCMSUser([]byte(payload))
	if err != nil {
		return "", err
	}

	// Create a new User record and a new CMSUser
	// record using a transaction.
	tx := c.userDB.Begin()
	err = c.updateCMSUser(tx, *uu)
	if err != nil {
		tx.Rollback()
		return "", err
	}
	err = tx.Commit().Error
	if err != nil {
		return "", err
	}

	// Prepare reply
	var uur user.UpdateCMSUserReply
	reply, err := user.EncodeUpdateCMSUserReply(uur)
	if err != nil {
		return "", nil
	}

	return string(reply), nil
}

// cmdCMSUsersByDomain returns all CMS users within the provided domain.
func (c *cockroachdb) cmdCMSUsersByDomain(payload string) (string, error) {
	// Decode payload
	p, err := user.DecodeCMSUsersByDomain([]byte(payload))
	if err != nil {
		return "", err
	}

	// Lookup cms users
	var users []CMSUser
	err = c.userDB.
		Where("domain = ?", p.Domain).
		Preload("User").
		Find(&users).
		Error
	if err != nil {
		return "", err
	}

	// Prepare reply
	u, err := c.convertCMSUsersFromDatabase(users)
	if err != nil {
		return "", err
	}
	r := user.CMSUsersByDomainReply{
		Users: u,
	}
	reply, err := user.EncodeCMSUsersByDomainReply(r)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdCMSUsersByContractorType returns all CMS users within the provided
// contractor type.
func (c *cockroachdb) cmdCMSUsersByContractorType(payload string) (string, error) {
	// Decode payload
	p, err := user.DecodeCMSUsersByContractorType([]byte(payload))
	if err != nil {
		return "", err
	}

	// Lookup cms users
	var users []CMSUser
	err = c.userDB.
		Where("contractor_type = ?", p.ContractorType).
		Preload("User").
		Find(&users).
		Error
	if err != nil {
		return "", err
	}

	// Prepare reply
	u, err := c.convertCMSUsersFromDatabase(users)
	if err != nil {
		return "", err
	}
	r := user.CMSUsersByContractorTypeReply{
		Users: u,
	}
	reply, err := user.EncodeCMSUsersByContractorTypeReply(r)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdCMSUsersByProposalToken returns all CMS users within the provided
// contractor type.
func (c *cockroachdb) cmdCMSUsersByProposalToken(payload string) (string, error) {
	// Decode payload
	p, err := user.DecodeCMSUsersByProposalToken([]byte(payload))
	if err != nil {
		return "", err
	}

	// Lookup cms users
	var users []CMSUser
	err = c.userDB.
		Where("'" + p.Token + "' = ANY(string_to_array(proposals_owned, ','))").
		Preload("User").
		Find(&users).
		Error
	if err != nil {
		return "", err
	}

	// Prepare reply
	u, err := c.convertCMSUsersFromDatabase(users)
	if err != nil {
		return "", err
	}
	r := user.CMSUsersByProposalTokenReply{
		Users: u,
	}
	reply, err := user.EncodeCMSUsersByProposalTokenReply(r)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdCMSUserByID returns the user information for a given user ID.
func (c *cockroachdb) cmdCMSUserByID(payload string) (string, error) {
	// Decode payload
	p, err := user.DecodeCMSUserByID([]byte(payload))
	if err != nil {
		return "", err
	}
	var cmsUser CMSUser
	err = c.userDB.
		Where("id = ?", p.ID).
		Preload("User").
		Find(&cmsUser).
		Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			// It's ok if there are no cms records found for this user.
			// But we do need to request the rest of the user details from the
			// www User table.
			var u User
			err = c.userDB.
				Where("id = ?", p.ID).
				Find(&u).
				Error
			if err != nil {
				if err == gorm.ErrRecordNotFound {
					err = user.ErrUserNotFound
				}
				return "", err
			}
			cmsUser.User = u
		} else {
			return "", err
		}
	}

	// Prepare reply
	u, err := c.convertCMSUserFromDatabase(cmsUser)
	if err != nil {
		return "", err
	}
	r := user.CMSUserByIDReply{
		User: u,
	}
	reply, err := user.EncodeCMSUserByIDReply(r)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (c *cockroachdb) cmdCMSUserSubContractors(payload string) (string, error) {
	// Decode payload
	p, err := user.DecodeCMSUserByID([]byte(payload))
	if err != nil {
		return "", err
	}
	var cmsUsers []CMSUser

	// This is done this way currently because GORM doesn't appear to properly
	// parse the following:
	// Where("? = ANY(string_to_array(supervisor_user_id, ','))", p.ID)
	err = c.userDB.
		Where("'" + p.ID + "' = ANY(string_to_array(supervisor_user_id, ','))").
		Preload("User").
		Find(&cmsUsers).
		Error
	if err != nil {
		return "", err
	}
	// Prepare reply
	subUsers := make([]user.CMSUser, 0, len(cmsUsers))
	for _, u := range cmsUsers {
		convertUser, err := c.convertCMSUserFromDatabase(u)
		if err != nil {
			return "", err
		}
		subUsers = append(subUsers, *convertUser)
	}
	r := user.CMSUserSubContractorsReply{
		Users: subUsers,
	}
	reply, err := user.EncodeCMSUserSubContractorsReply(r)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// Exec executes a cms plugin command.
func (c *cockroachdb) cmsPluginExec(cmd, payload string) (string, error) {
	switch cmd {
	case user.CmdNewCMSUser:
		return c.cmdNewCMSUser(payload)
	case user.CmdCMSUsersByDomain:
		return c.cmdCMSUsersByDomain(payload)
	case user.CmdCMSUsersByContractorType:
		return c.cmdCMSUsersByContractorType(payload)
	case user.CmdUpdateCMSUser:
		return c.cmdUpdateCMSUser(payload)
	case user.CmdCMSUserByID:
		return c.cmdCMSUserByID(payload)
	case user.CmdCMSUserSubContractors:
		return c.cmdCMSUserSubContractors(payload)
	case user.CmdCMSUsersByProposalToken:
		return c.cmdCMSUsersByProposalToken(payload)
	default:
		return "", user.ErrInvalidPluginCmd
	}
}

// cmsPluginCreateTables creates all cms plugin tables and inserts a cms
// plugin version record into the database.
//
// This function must be called using a transaction.
func (c *cockroachdb) cmsPluginCreateTables(tx *gorm.DB) error {
	if !tx.HasTable(tableCMSUsers) {
		// Build tables
		err := tx.CreateTable(&CMSUser{}).Error
		if err != nil {
			return err
		}
		// Insert version record
		kv := KeyValue{
			Key:   user.CMSPluginID,
			Value: []byte(user.CMSPluginVersion),
		}
		err = tx.Create(&kv).Error
		if err != nil {
			return err
		}
	}

	return nil
}

// cmsPluginSetup creates all cms plugin tables and ensures the database
// is using the correct cms plugin version.
func (c *cockroachdb) cmsPluginSetup() error {
	// Setup database tables
	tx := c.userDB.Begin()
	err := c.cmsPluginCreateTables(tx)
	if err != nil {
		tx.Rollback()
		return err
	}

	err = tx.Commit().Error
	if err != nil {
		return err
	}

	// Check version record
	kv := KeyValue{
		Key: user.CMSPluginID,
	}
	err = c.userDB.Find(&kv).Error
	if err != nil {
		return err
	}

	// XXX a version mismatch will need to trigger a
	// migration but just return an error for now.
	if string(kv.Value) != user.CMSPluginVersion {
		return fmt.Errorf("wrong plugin version")
	}

	return nil
}
