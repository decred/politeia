package mysql

import (
	"database/sql"
	"fmt"
	"time"

	v2 "github.com/decred/politeia/politeiawww/api/cms/v2"
	"github.com/decred/politeia/politeiawww/legacy/user"
	_ "github.com/go-sql-driver/mysql"
)

const (
	tableNameCMSUser = "cms_user"
)

/*
type CMSUser struct {
	ID                 uuid.UUID `gorm:"primary_key"` // UUID (User foreign key)
	Domain             int       `gorm:"not null"`    // Contractor domain
	GitHubName         string    `gorm:"not null"`    // Github Name/ID
	MatrixName         string    `gorm:"not null"`    // Matrix Name/ID
	ContractorType     int       `gorm:"not null"`    // Type of Contractor
	ContractorName     string    `gorm:"not null"`    // IRL Contractor Name or identity
	ContractorLocation string    `gorm:"not null"`    // General IRL Contractor Location
	ContractorContact  string    `gorm:"not null"`    // Point of contact outside of matrix
	SupervisorUserID   string    `gorm:"not null"`    // This is can either be 1 SupervisorUserID or a comma separated string of many supervisor user ids
	ProposalsOwned     string    `gorm:"not null"`    // This can either be 1 Proposal or a comma separated string of many.

	// Set by gorm
	CreatedAt time.Time // Time of record creation
	UpdatedAt time.Time // Time of last record update
}
*/
// tableCMSuser defines the cms_user table.
const tableCMSuser = `
id VARCHAR(36) NOT NULL PRIMARY KEY,
domain INT(11) NOT NULL,
github_name VARCHAR(255),
matrix_name VARCHAR(255),
contractor_type INT(11) NOT NULL,
contractor_name VARCHAR(255),
contractor_location VARCHAR(255),
contractor_contact VARCHAR(255),
supervisor_user_id VARCHAR(36),
proposals_owned VARCHAR(640),
created_at INT(11) NOT NULL,
updated_at INT(11),
FOREIGN KEY (id) REFERENCES users(id)
`

// newCMSUser creates a new User record and a corresponding CMSUser record
// with the provided user info.
//
// This function must be called using a transaction.
func (m *mysql) newCMSUser(tx *sql.Tx, nu user.NewCMSUser) error {
	ctx, cancel := ctxWithTimeout()
	defer cancel()

	// Create a new User record
	u := user.User{
		Email:                     nu.Email,
		Username:                  nu.Username,
		NewUserVerificationToken:  nu.NewUserVerificationToken,
		NewUserVerificationExpiry: nu.NewUserVerificationExpiry,
	}
	id, err := m.userNew(ctx, tx, u)
	if err != nil {
		return err
	}

	ur := struct {
		ID             string
		Username       string
		CreatedAt      int64
		Domain         int
		ContractorType int
	}{
		ID:             u.ID.String(),
		Username:       u.Username,
		Domain:         int(v2.DomainTypeInvalid),
		ContractorType: int(v2.ContractorTypeNominee),

		CreatedAt: time.Now().Unix(),
	}
	_, err = tx.ExecContext(ctx,
		"INSERT INTO cms_user (id, domain, contractor_type, created_at) VALUES (?, ?, ?, ?)",
		id, ur.Domain, ur.ContractorType, ur.CreatedAt)
	if err != nil {
		return fmt.Errorf("create user: %v", err)
	}
	return nil
}

// cmdNewCMSUser inserts a new CMSUser record into the database.
func (m *mysql) cmdNewCMSUser(payload string) (string, error) {
	// Decode payload
	nu, err := user.DecodeNewCMSUser([]byte(payload))
	if err != nil {
		return "", err
	}

	log.Tracef("cmdNewCMSUser: %v", nu.Username)

	if m.isShutdown() {
		return "", user.ErrShutdown
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	// Start transaction.
	opts := &sql.TxOptions{
		Isolation: sql.LevelDefault,
	}
	tx, err := m.userDB.BeginTx(ctx, opts)
	if err != nil {
		return "", fmt.Errorf("begin tx: %v", err)
	}
	defer tx.Rollback()

	err = m.newCMSUser(tx, *nu)
	if err != nil {
		tx.Rollback()
		return "", err
	}

	// Commit transaction.
	if err := tx.Commit(); err != nil {
		if err2 := tx.Rollback(); err2 != nil {
			// We're in trouble!
			panic(fmt.Errorf("rollback tx failed: commit:'%v' rollback:'%v'",
				err, err2))
		}
		return "", fmt.Errorf("commit tx: %v", err)
	}

	// Prepare reply
	var nur user.NewCMSUserReply
	reply, err := user.EncodeNewCMSUserReply(nur)
	if err != nil {
		return "", nil
	}

	return string(reply), nil
}

/*
// updateCMSUser updates an existing  CMSUser record with the provided user
// info.
//
// This function must be called using a transaction.
func (m *mysql) updateCMSUser(tx *gorm.DB, nu user.UpdateCMSUser) error {
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
func (m *mysql) cmdUpdateCMSUser(payload string) (string, error) {
	// Decode payload
	uu, err := user.DecodeUpdateCMSUser([]byte(payload))
	if err != nil {
		return "", err
	}

	// Create a new User record and a new CMSUser
	// record using a transaction.
	tx := m.userDB.Begin()
	err = m.updateCMSUser(tx, *uu)
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
func (m *mysql) cmdCMSUsersByDomain(payload string) (string, error) {
	// Decode payload
	p, err := user.DecodeCMSUsersByDomain([]byte(payload))
	if err != nil {
		return "", err
	}

	// Lookup cms users
	var users []CMSUser
	err = m.userDB.
		Where("domain = ?", p.Domain).
		Preload("User").
		Find(&users).
		Error
	if err != nil {
		return "", err
	}

	// Prepare reply
	u, err := m.convertCMSUsersFromDatabase(users)
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
func (m *mysql) cmdCMSUsersByContractorType(payload string) (string, error) {
	// Decode payload
	p, err := user.DecodeCMSUsersByContractorType([]byte(payload))
	if err != nil {
		return "", err
	}

	// Lookup cms users
	var users []CMSUser
	err = m.userDB.
		Where("contractor_type = ?", p.ContractorType).
		Preload("User").
		Find(&users).
		Error
	if err != nil {
		return "", err
	}

	// Prepare reply
	u, err := m.convertCMSUsersFromDatabase(users)
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
func (m *mysql) cmdCMSUsersByProposalToken(payload string) (string, error) {
	// Decode payload
	p, err := user.DecodeCMSUsersByProposalToken([]byte(payload))
	if err != nil {
		return "", err
	}

	// Lookup cms users
	var users []CMSUser
	err = m.userDB.
		Where("'" + p.Token + "' = ANY(string_to_array(proposals_owned, ','))").
		Preload("User").
		Find(&users).
		Error
	if err != nil {
		return "", err
	}

	// Prepare reply
	u, err := m.convertCMSUsersFromDatabase(users)
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
func (m *mysql) cmdCMSUserByID(payload string) (string, error) {
	// Decode payload
	p, err := user.DecodeCMSUserByID([]byte(payload))
	if err != nil {
		return "", err
	}
	var cmsUser CMSUser
	err = m.userDB.
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
			err = m.userDB.
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
	u, err := m.convertCMSUserFromDatabase(cmsUser)
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

func (m *mysql) cmdCMSUserSubContractors(payload string) (string, error) {
	// Decode payload
	p, err := user.DecodeCMSUserByID([]byte(payload))
	if err != nil {
		return "", err
	}
	var cmsUsers []CMSUser

	// This is done this way currently because GORM doesn't appear to properly
	// parse the following:
	// Where("? = ANY(string_to_array(supervisor_user_id, ','))", p.ID)
	err = m.userDB.
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
		convertUser, err := m.convertCMSUserFromDatabase(u)
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

// NewCMSCodeStats is an exported function (for testing) to insert a new
// code stats row into the cms_code_stats table.
func (m *mysql) NewCMSCodeStats(nu *user.NewCMSCodeStats) error {

	tx := m.userDB.Begin()
	for _, ncs := range nu.UserCodeStats {
		cms := convertCodestatsToDatabase(ncs)
		err := m.newCMSCodeStats(tx, cms)
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit().Error
}

// cmdNewCMSCodeStats inserts a new CMSUser record into the database.
func (m *mysql) cmdNewCMSCodeStats(payload string) (string, error) {
	// Decode payload
	nu, err := user.DecodeNewCMSCodeStats([]byte(payload))
	if err != nil {
		return "", err
	}
	err = m.NewCMSCodeStats(nu)
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
func (m *mysql) cmdUpdateCMSCodeStats(payload string) (string, error) {
	// Decode payload
	nu, err := user.DecodeUpdateCMSCodeStats([]byte(payload))
	if err != nil {
		return "", err
	}

	err = m.UpdateCMSCodeStats(nu)
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

func (m *mysql) UpdateCMSCodeStats(ucs *user.UpdateCMSCodeStats) error {
	tx := m.userDB.Begin()
	for _, ncs := range ucs.UserCodeStats {
		cms := convertCodestatsToDatabase(ncs)
		err := m.updateCMSCodeStats(tx, cms)
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit().Error
}

// updateCMSCodeStats updates a CMS Code stats record
//
// This function must be called using a transaction.
func (m *mysql) updateCMSCodeStats(tx *gorm.DB, cs CMSCodeStats) error {
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
func (m *mysql) newCMSCodeStats(tx *gorm.DB, cs CMSCodeStats) error {
	err := tx.Create(&cs).Error
	if err != nil {
		return err
	}
	return nil
}

func (m *mysql) cmdCMSCodeStatsByUserMonthYear(payload string) (string, error) {
	// Decode payload
	p, err := user.DecodeCMSCodeStatsByUserMonthYear([]byte(payload))
	if err != nil {
		return "", err
	}

	userCodeStats, err := m.CMSCodeStatsByUserMonthYear(p)
	if err != nil {
		return "", err
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

func (m *mysql) CMSCodeStatsByUserMonthYear(p *user.CMSCodeStatsByUserMonthYear) ([]user.CodeStats, error) {
	var cmsCodeStats []CMSCodeStats
	err := m.userDB.
		Where("git_hub_name = ? AND month = ? AND year = ?", p.GithubName,
			p.Month, p.Year).
		Find(&cmsCodeStats).
		Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = user.ErrCodeStatsNotFound
			return nil, err
		}
		return nil, err
	}
	// Prepare reply
	userCodeStats := make([]user.CodeStats, 0, len(cmsCodeStats))
	for _, u := range cmsCodeStats {
		userCodeStats = append(userCodeStats, convertCodestatsFromDatabase(u))
	}
	return userCodeStats, nil
}
*/
// Exec executes a cms plugin command.
func (m *mysql) cmsPluginExec(cmd, payload string) (string, error) {
	switch cmd {
	case user.CmdNewCMSUser:
		return m.cmdNewCMSUser(payload)
		/*
			case user.CmdCMSUsersByDomain:
				return m.cmdCMSUsersByDomain(payload)
			case user.CmdCMSUsersByContractorType:
				return m.cmdCMSUsersByContractorType(payload)
			case user.CmdUpdateCMSUser:
				return m.cmdUpdateCMSUser(payload)
			case user.CmdCMSUserByID:
				return m.cmdCMSUserByID(payload)
			case user.CmdCMSUserSubContractors:
				return m.cmdCMSUserSubContractors(payload)
			case user.CmdCMSUsersByProposalToken:
				return m.cmdCMSUsersByProposalToken(payload)
			case user.CmdNewCMSUserCodeStats:
				return m.cmdNewCMSCodeStats(payload)
			case user.CmdUpdateCMSUserCodeStats:
				return m.cmdUpdateCMSCodeStats(payload)
			case user.CmdCMSCodeStatsByUserMonthYear:
				return m.cmdCMSCodeStatsByUserMonthYear(payload)
		*/
	default:
		return "", user.ErrInvalidPluginCmd
	}
}

// cmsPluginCreateTables creates all cms plugin tables and inserts a cms
// plugin version record into the database.
//
// This function must be called using a transaction.
func (m *mysql) cmsPluginCreateTables(tx *sql.Tx) error {
	q := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %v (%v)`,
		tableNameCMSUser, tableCMSuser)
	_, err := tx.Exec(q)
	if err != nil {
		return fmt.Errorf("create %v table: %v",
			tableNameCMSUser, err)
	}
	return nil
}

// cmsPluginSetup creates all cms plugin tables and ensures the database
// is using the correct cms plugin version.
func (m *mysql) cmsPluginSetup() error {
	ctx, cancel := ctxWithTimeout()
	defer cancel()

	// Init a sql transaction.
	opts := &sql.TxOptions{
		Isolation: sql.LevelDefault,
	}
	tx, err := m.userDB.BeginTx(ctx, opts)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	err = m.cmsPluginCreateTables(tx)
	if err != nil {
		tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		if err2 := tx.Rollback(); err2 != nil {
			// We're in trouble!
			panic(fmt.Errorf("rollback tx failed: commit:'%v' rollback:'%v'",
				err, err2))
		}
		return fmt.Errorf("commit tx: %v", err)
	}

	return nil
}
