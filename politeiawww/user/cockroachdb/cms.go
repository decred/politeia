package cockroachdb

import (
	"errors"
	"fmt"

	"github.com/decred/politeia/politeiawww/user"
	"github.com/jinzhu/gorm"
)

const (
	// CMS plugin table names
	tableCMSUsers     = "cms_users"
	tableCMSCodeStats = "cms_code_stats"
)

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
		if errors.Is(err, gorm.ErrRecordNotFound) {
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
	if nu.Domain != 0 {
		cms.Domain = nu.Domain
	}
	if nu.GitHubName != "" {
		cms.GitHubName = nu.GitHubName
	}
	if nu.MatrixName != "" {
		cms.MatrixName = nu.MatrixName
	}
	if nu.ContractorName != "" {
		cms.ContractorName = nu.ContractorName
	}
	if nu.ContractorType != 0 {
		cms.ContractorType = nu.ContractorType
	}
	if nu.ContractorLocation != "" {
		cms.ContractorLocation = nu.ContractorLocation
	}
	if nu.ContractorContact != "" {
		cms.ContractorContact = nu.ContractorContact
	}
	if superVisorUserIds != "" {
		cms.SupervisorUserID = superVisorUserIds
	}
	if proposalsOwned != "" {
		cms.ProposalsOwned = proposalsOwned
	}

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
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// It's ok if there are no cms records found for this user.
			// But we do need to request the rest of the user details from the
			// www User table.
			var u User
			err = c.userDB.
				Where("id = ?", p.ID).
				Find(&u).
				Error
			if err != nil {
				if errors.Is(err, gorm.ErrRecordNotFound) {
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

// cmdNewCMSCodeStats inserts a new CMSUser record into the database.
func (c *cockroachdb) cmdNewCMSCodeStats(payload string) (string, error) {
	// Decode payload
	nu, err := user.DecodeNewCMSCodeStats([]byte(payload))
	if err != nil {
		return "", err
	}

	tx := c.userDB.Begin()
	for _, ncs := range nu.UserCodeStats {
		cms := convertCodestatsToDatabase(ncs)
		err = c.newCMSCodeStats(tx, cms)
		if err != nil {
			tx.Rollback()
			return "", err
		}
	}
	err = tx.Commit().Error
	if err != nil {
		return "", err
	}

	// Prepare reply
	var nur user.NewCMSCodeStatsReply
	reply, err := user.EncodeNewCMSCodeStatsReply(nur)
	if err != nil {
		return "", nil
	}

	return string(reply), nil
}

// cmdUpdateCMSCodeStats updates an existing CMSUser record into the database.
func (c *cockroachdb) cmdUpdateCMSCodeStats(payload string) (string, error) {
	// Decode payload
	nu, err := user.DecodeUpdateCMSCodeStats([]byte(payload))
	if err != nil {
		return "", err
	}

	tx := c.userDB.Begin()
	for _, ncs := range nu.UserCodeStats {
		cms := convertCodestatsToDatabase(ncs)
		err = c.updateCMSCodeStats(tx, cms)
		if err != nil {
			tx.Rollback()
			return "", err
		}
	}
	err = tx.Commit().Error
	if err != nil {
		return "", err
	}

	// Prepare reply
	var nur user.UpdateCMSCodeStatsReply
	reply, err := user.EncodeUpdateCMSCodeStatsReply(nur)
	if err != nil {
		return "", nil
	}

	return string(reply), nil
}

// updateCMSCodeStats updates a CMS Code stats record
//
// This function must be called using a transaction.
func (c *cockroachdb) updateCMSCodeStats(tx *gorm.DB, cs CMSCodeStats) error {
	err := tx.Save(&cs).Error
	if err != nil {
		return err
	}
	return nil
}

// newCMSCodeStats creates a new User record and a corresponding CMSUser record
// with the provided user info.
//
// This function must be called using a transaction.
func (c *cockroachdb) newCMSCodeStats(tx *gorm.DB, cs CMSCodeStats) error {
	err := tx.Create(&cs).Error
	if err != nil {
		return err
	}
	return nil
}

func (c *cockroachdb) cmdCMSCodeStatsByUserMonthYear(payload string) (string, error) {
	// Decode payload
	p, err := user.DecodeCMSCodeStatsByUserMonthYear([]byte(payload))
	if err != nil {
		return "", err
	}
	var cmsCodeStats []CMSCodeStats

	// This is done this way currently because GORM doesn't appear to properly
	// parse the following:
	// Where("? = ANY(string_to_array(supervisor_user_id, ','))", p.ID)
	err = c.userDB.
		Where("git_hub_name = ? AND month = ? and year = ?", p.GithubName, p.Month, p.Year).
		Find(&cmsCodeStats).
		Error
	if err != nil {
		return "", err
	}
	// Prepare reply
	userCodeStats := make([]user.CodeStats, 0, len(cmsCodeStats))
	for _, u := range cmsCodeStats {
		codeStat := convertCodestatsFromDatabase(u)
		if err != nil {
			return "", err
		}
		userCodeStats = append(userCodeStats, codeStat)
	}
	r := user.CMSCodeStatsByUserMonthYearReply{
		UserCodeStats: userCodeStats,
	}
	reply, err := user.EncodeCMSCodeStatsByUserMonthYearReply(r)
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
	case user.CmdNewCMSUserCodeStats:
		return c.cmdNewCMSCodeStats(payload)
	case user.CmdUpdateCMSUserCodeStats:
		return c.cmdUpdateCMSCodeStats(payload)
	case user.CmdCMSCodeStatsByUserMonthYear:
		return c.cmdCMSCodeStatsByUserMonthYear(payload)
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
	if !tx.HasTable(tableCMSCodeStats) {
		err := tx.CreateTable(&CMSCodeStats{}).Error
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
