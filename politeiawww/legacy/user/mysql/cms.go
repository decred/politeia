package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	v2 "github.com/decred/politeia/politeiawww/api/cms/v2"
	"github.com/decred/politeia/politeiawww/legacy/user"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
)

const (
	tableNameCMSUser      = "cms_user"
	tableNameCMSCodeStats = "cms_code_stats"
)

type CMSUser struct {
	ID                 string
	Domain             int
	GitHubName         string
	MatrixName         string
	ContractorType     int
	ContractorName     string
	ContractorLocation string
	ContractorContact  string
	SupervisorUserID   string
	ProposalsOwned     string

	// Set by gorm
	CreatedAt time.Time // Time of record creation
	UpdatedAt time.Time // Time of last record update
}

// CMSCodeStats struct contains information per month/year per repo for
// a given users' code statistics for merged pull requests and completed
// reviews over that time period.
type CMSCodeStats struct {
	ID               string
	GitHubName       string
	Repository       string
	Month            int
	Year             int
	PRs              string
	Reviews          string
	Commits          string
	MergedAdditions  int64
	MergedDeletions  int64
	UpdatedAdditions int64
	UpdatedDeletions int64
	ReviewAdditions  int64
	ReviewDeletions  int64
	CommitAdditions  int64
	CommitDeletions  int64
}

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

// tableCMSuser defines the cms_user table.
const tableCMSCodeStats = `
id VARCHAR(36) NOT NULL PRIMARY KEY,
github_name VARCHAR(255) NOT NULL,
repository VARCHAR(255) NOT NULL,
month INT(11) NOT NULL,
year INT(11) NOT NULL,
prs VARCHAR(255) NOT NULL,
reviews VARCHAR(255) NOT NULL,
commits VARCHAR(255) NOT NULL,
merged_additions INT(11) NOT NULL,
merged_deletions INT(11) NOT NULL,
updated_additions INT(11) NOT NULL,
updated_deletions INT(11) NOT NULL,
review_additions INT(11) NOT NULL,
review_deletions INT(11) NOT NULL,
commit_additions INT(11) NOT NULL,
commit_deletions INT(11) NOT NULL
`

// newCMSUser creates a new User record and a corresponding CMSUser record
// with the provided user info.
//
// This function must be called using a transaction.
func (m *mysql) newCMSUser(ctx context.Context, tx *sql.Tx, nu user.NewCMSUser) error {
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

	err = m.newCMSUser(ctx, tx, *nu)
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

// updateCMSUser updates an existing  CMSUser record with the provided user
// info.
//
// This function must be called using a transaction.
func (m *mysql) updateCMSUser(ctx context.Context, tx *sql.Tx, nu user.UpdateCMSUser) error {
	cms := CMSUser{
		ID: nu.ID.String(),
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

	err := m.userDB.QueryRowContext(ctx,
		"SELECT * FROM cms_user WHERE id = ?", cms.ID).Scan(&cms)
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
			cms.CreatedAt = time.Now()
			_, err = tx.ExecContext(ctx,
				"INSERT INTO cms_user (id, domain, github_name, matrix_name, "+
					"contractor_name, contractor_type, contractor_location, "+
					"contractor_contact, supervisor_user_id, proposals_owned, "+
					"created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
				cms.ID, cms.Domain, cms.GitHubName, cms.MatrixName,
				cms.ContractorType, cms.ContractorName, cms.ContractorLocation,
				cms.ContractorContact, cms.SupervisorUserID, cms.ProposalsOwned,
				cms.CreatedAt.Unix())
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
	cms.UpdatedAt = time.Now()
	_, err = tx.ExecContext(ctx,
		"UPDATE cms_user SET domain = ?, github_name = ?, matrix_name = ?, "+
			"contractor_type = ?, contractor_name = ?, contractor_location = ?, "+
			"contractor_contact = ?, supervisor_user_id = ?, "+
			"proposals_owned = ?, updated_at = ? WHERE id = ? ",
		cms.Domain, cms.GitHubName, cms.MatrixName, cms.ContractorType,
		cms.ContractorName, cms.ContractorLocation, cms.ContractorContact,
		cms.SupervisorUserID, cms.ProposalsOwned, cms.UpdatedAt.Unix(), cms.ID)
	if err != nil {
		return fmt.Errorf("update user: %v", err)
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

	err = m.updateCMSUser(ctx, tx, *uu)
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
	ud, err := user.DecodeCMSUsersByDomain([]byte(payload))
	if err != nil {
		return "", err
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	// Lookup users by domain.
	q := `SELECT 
		  id,
		  github_name,
		  matrix_name,
		  contractor_type,
		  contractor_name,
		  contractor_contact,
		  contractor_location,
		  supervisor_user_id,
		  proposals_owned
          FROM cms_user
          WHERE domain = ?`

	rows, err := m.userDB.QueryContext(ctx, q, ud.Domain)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	cmsUsers := make([]user.CMSUser, 0)
	for rows.Next() {
		cmsUser := CMSUser{}
		err := rows.Scan(&cmsUser.ID, &cmsUser.GitHubName, &cmsUser.MatrixName,
			&cmsUser.ContractorType, &cmsUser.ContractorContact,
			&cmsUser.ContractorLocation, &cmsUser.SupervisorUserID,
			&cmsUser.ProposalsOwned)
		if err != nil {
			return "", err
		}
		cmsUser.Domain = ud.Domain
		convertedUser, err := convertCMSUserFromDatabase(cmsUser)
		if err != nil {
			return "", err
		}
		cmsUsers = append(cmsUsers, *convertedUser)
	}

	if err = rows.Err(); err != nil {
		return err
	}

	r := user.CMSUsersByDomainReply{
		Users: cmsUsers,
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
	uct, err := user.DecodeCMSUsersByContractorType([]byte(payload))
	if err != nil {
		return "", err
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	// Lookup users by domain.
	q := `SELECT 
		  id,
		  domain,
		  github_name,
		  matrix_name,
		  contractor_type,
		  contractor_name,
		  contractor_contact,
		  contractor_location,
		  supervisor_user_id,
		  proposals_owned
          FROM cms_user
          WHERE domain = ?`

	rows, err := m.userDB.QueryContext(ctx, q, uct.ContractorType)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	cmsUsers := make([]user.CMSUser, 0)
	for rows.Next() {
		cmsUser := CMSUser{}
		err := rows.Scan(&cmsUser.ID, &cmsUser.Domain, &cmsUser.GitHubName,
			&cmsUser.MatrixName, &cmsUser.ContractorType,
			&cmsUser.ContractorContact, &cmsUser.ContractorLocation,
			&cmsUser.SupervisorUserID, &cmsUser.ProposalsOwned)
		if err != nil {
			return "", err
		}
		convertedUser, err := convertCMSUserFromDatabase(cmsUser)
		if err != nil {
			return "", err
		}
		cmsUsers = append(cmsUsers, *convertedUser)
	}

	if err = rows.Err(); err != nil {
		return err
	}

	r := user.CMSUsersByContractorTypeReply{
		Users: cmsUsers,
	}
	reply, err := user.EncodeCMSUsersByContractorTypeReply(r)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// cmdCMSUsersByProposalToken returns all CMS that have a given proposal token
// set for proposals owned.
func (m *mysql) cmdCMSUsersByProposalToken(payload string) (string, error) {
	// Decode payload
	upt, err := user.DecodeCMSUsersByProposalToken([]byte(payload))
	if err != nil {
		return "", err
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()

	// Lookup users by proposaltoken.
	q := `SELECT 
		  id,
		  domain,
		  github_name,
		  matrix_name,
		  contractor_type,
		  contractor_name,
		  contractor_contact,
		  contractor_location,
		  supervisor_user_id,
		  proposals_owned
          FROM cms_user
          WHERE ANY(string_to_array(proposals_owned, ',') = ?`

	rows, err := m.userDB.QueryContext(ctx, q, upt.Token)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	cmsUsers := make([]user.CMSUser, 0)
	for rows.Next() {
		cmsUser := CMSUser{}
		err := rows.Scan(&cmsUser.ID, &cmsUser.Domain, &cmsUser.GitHubName,
			&cmsUser.MatrixName, &cmsUser.ContractorType,
			&cmsUser.ContractorContact, &cmsUser.ContractorLocation,
			&cmsUser.SupervisorUserID, &cmsUser.ProposalsOwned)
		if err != nil {
			return "", err
		}

		convertedUser, err := convertCMSUserFromDatabase(cmsUser)
		if err != nil {
			return "", err
		}
		cmsUsers = append(cmsUsers, *convertedUser)
	}

	if err = rows.Err(); err != nil {
		return err
	}

	r := user.CMSUsersByProposalTokenReply{
		Users: cmsUsers,
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
	uid, err := user.DecodeCMSUserByID([]byte(payload))
	if err != nil {
		return "", err
	}

	ctx, cancel := ctxWithTimeout()
	defer cancel()
	q := `SELECT 
		id,
		domain,
		github_name,
		matrix_name,
		contractor_type,
		contractor_name,
		contractor_contact,
		contractor_location,
		supervisor_user_id,
		proposals_owned
		FROM cms_user
		WHERE id = ?`
	cmsUser := CMSUser{}
	err = m.userDB.QueryRowContext(ctx, q, uid.ID).Scan(&cmsUser.ID,
		&cmsUser.Domain, &cmsUser.GitHubName,
		&cmsUser.MatrixName, &cmsUser.ContractorType,
		&cmsUser.ContractorContact, &cmsUser.ContractorLocation,
		&cmsUser.SupervisorUserID, &cmsUser.ProposalsOwned)
	if err != nil {
		return "", err
	}

	convertedUser, err := convertCMSUserFromDatabase(cmsUser)
	if err != nil {
		return "", err
	}
	r := user.CMSUserByIDReply{
		User: convertedUser,
	}
	reply, err := user.EncodeCMSUserByIDReply(r)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (m *mysql) cmdCMSUserSubContractors(payload string) (string, error) {
	// Decode payload
	sbc, err := user.DecodeCMSUserSubContractors([]byte(payload))
	if err != nil {
		return "", err
	}
	ctx, cancel := ctxWithTimeout()
	defer cancel()

	// Lookup users by proposaltoken.
	q := `SELECT 
		  id,
		  domain,
		  github_name,
		  matrix_name,
		  contractor_type,
		  contractor_name,
		  contractor_contact,
		  contractor_location,
		  supervisor_user_id,
		  proposals_owned
          FROM cms_user
          WHERE ANY(string_to_array(supervisor_user_id, ',') = ?`

	rows, err := m.userDB.QueryContext(ctx, q, sbc.ID)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	cmsUsers := make([]user.CMSUser, 0)
	for rows.Next() {
		cmsUser := CMSUser{}
		err := rows.Scan(&cmsUser.ID, &cmsUser.Domain, &cmsUser.GitHubName,
			&cmsUser.MatrixName, &cmsUser.ContractorType,
			&cmsUser.ContractorContact, &cmsUser.ContractorLocation,
			&cmsUser.SupervisorUserID, &cmsUser.ProposalsOwned)
		if err != nil {
			return "", err
		}

		convertedUser, err := convertCMSUserFromDatabase(cmsUser)
		if err != nil {
			return "", err
		}
		cmsUsers = append(cmsUsers, *convertedUser)
	}

	r := user.CMSUserSubContractorsReply{
		Users: cmsUsers,
	}
	reply, err := user.EncodeCMSUserSubContractorsReply(r)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (m *mysql) newCMSCodeStats(ctx context.Context, tx *sql.Tx, nu *user.NewCMSCodeStats) error {
	for _, ncs := range nu.UserCodeStats {
		var prs string
		for i, pr := range ncs.PRs {
			if i == 0 {
				prs = pr
			} else {
				prs += ", " + pr
			}
		}
		var reviews string
		for i, review := range ncs.Reviews {
			if i == 0 {
				reviews = review
			} else {
				reviews += ", " + review
			}
		}
		var commits string
		for i, commit := range ncs.Commits {
			if i == 0 {
				commits = commit
			} else {
				commits += ", " + commit
			}
		}
		id := fmt.Sprintf("%v-%v-%v-%v", ncs.GitHubName, ncs.Repository,
			strconv.Itoa(ncs.Month), strconv.Itoa(ncs.Year))
		log.Tracef("newCMSCodeStats: %v", id)
		_, err := tx.ExecContext(ctx,
			`INSERT INTO cms_code_stats (
				id,
				github_name,
				repository,
				month,
				year,
				prs,
				reviews,
				commits,
				merged_additions,
				merged_deletions,
				updated_additions,
				updated_deletions,
				review_additions,
				review_deletions,
				commit_additions,
				commit_deletions) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, ncs.GitHubName, ncs.Repository, ncs.Month, ncs.Year, prs,
			reviews, commits, ncs.MergedAdditions, ncs.MergedDeletions,
			ncs.UpdatedAdditions, ncs.UpdatedDeletions, ncs.ReviewAdditions,
			ncs.ReviewDeletions, ncs.CommitAdditions, ncs.CommitDeletions)
		if err != nil {
			return fmt.Errorf("create user: %v", err)
		}
	}
	return nil
}

// cmdNewCMSCodeStats inserts a new CMSUser record into the database.
func (m *mysql) cmdNewCMSCodeStats(payload string) (string, error) {
	// Decode payload
	ncs, err := user.DecodeNewCMSCodeStats([]byte(payload))
	if err != nil {
		return "", err
	}

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

	err = m.newCMSCodeStats(ctx, tx, ncs)
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
	ucs, err := user.DecodeUpdateCMSCodeStats([]byte(payload))
	if err != nil {
		return "", err
	}

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

	err = m.updateCMSCodeStats(ctx, tx, ucs.UserCodeStats)
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
func (m *mysql) updateCMSCodeStats(ctx context.Context, tx *sql.Tx, ucs []user.CodeStats) error {
	for _, cs := range ucs {
		var prs string
		for i, pr := range cs.PRs {
			if i == 0 {
				prs = pr
			} else {
				prs += ", " + pr
			}
		}
		var reviews string
		for i, review := range cs.Reviews {
			if i == 0 {
				reviews = review
			} else {
				reviews += ", " + review
			}
		}
		var commits string
		for i, commit := range cs.Commits {
			if i == 0 {
				commits = commit
			} else {
				commits += ", " + commit
			}
		}
		id := fmt.Sprintf("%v-%v-%v-%v", cs.GitHubName, cs.Repository,
			strconv.Itoa(cs.Month), strconv.Itoa(cs.Year))
		log.Tracef("newCMSCodeStats: %v", id)
		_, err := tx.ExecContext(ctx,
			`UPDATE cms_code_stats SET ,
			github_name = ?,
			repository = ?,
			month = ?,
			year = ?,
			prs = ?,
			reviews = ?,
			commits = ?,
			merged_additions = ?,
			merged_deletions = ?,
			updated_additions = ?,
			updated_deletions = ?,
			review_additions = ?,
			review_deletions = ?,
			commit_additions = ?,
			commit_deletions = ? WHERE id = ?`,
			id, cs.GitHubName, cs.Repository, cs.Month, cs.Year, prs, reviews,
			commits, cs.MergedAdditions, cs.MergedDeletions,
			cs.UpdatedAdditions, cs.UpdatedDeletions, cs.ReviewAdditions,
			cs.ReviewDeletions, cs.CommitAdditions, cs.CommitDeletions)
		if err != nil {
			return fmt.Errorf("update user: %v", err)
		}
	}

	return nil
}

func (m *mysql) cmdCMSCodeStatsByUserMonthYear(payload string) (string, error) {
	// Decode payload
	csumy, err := user.DecodeCMSCodeStatsByUserMonthYear([]byte(payload))
	if err != nil {
		return "", err
	}
	ctx, cancel := ctxWithTimeout()
	defer cancel()

	q := `SELECT 
		id,
		github_name,
		repository,
		month,
		year,
		prs,
		reviews,
		commits,
		merged_additions,
		merged_deletions,
		updated_additions,
		updated_deletions,
		review_additions,
		review_deletions,
		commit_additions,
		commit_deletions
		WHERE github_name = ? AND month = ? AND year = ?`
	if err != nil {
		return "", err
	}

	rows, err := m.userDB.QueryContext(ctx, q, csumy.GithubName, csumy.Month, csumy.Year)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	cmsCodeStats := make([]user.CodeStats, 0)
	for rows.Next() {
		cs := CMSCodeStats{}
		err := rows.Scan(cs.ID, cs.GitHubName, cs.Repository, cs.Month, cs.Year,
			cs.PRs, cs.Reviews, cs.Commits, cs.MergedAdditions,
			cs.MergedDeletions, cs.UpdatedAdditions, cs.UpdatedDeletions,
			cs.ReviewAdditions, cs.ReviewDeletions, cs.CommitAdditions,
			cs.CommitDeletions)
		if err != nil {
			return "", err
		}

		convertedUser := convertCodestatsFromDatabase(cs)
		if err != nil {
			return "", err
		}
		cmsCodeStats = append(cmsCodeStats, convertedUser)
	}

	r := user.CMSCodeStatsByUserMonthYearReply{
		UserCodeStats: cmsCodeStats,
	}
	reply, err := user.EncodeCMSCodeStatsByUserMonthYearReply(r)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// Exec executes a cms plugin command.
func (m *mysql) cmsPluginExec(cmd, payload string) (string, error) {
	switch cmd {
	case user.CmdNewCMSUser:
		return m.cmdNewCMSUser(payload)
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
		return fmt.Errorf("create %v table: %v", tableNameCMSUser, err)
	}
	q = fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %v (%v)`,
		tableNameCMSCodeStats, tableCMSCodeStats)
	_, err = tx.Exec(q)
	if err != nil {
		return fmt.Errorf("create %v table: %v", tableNameCMSCodeStats, err)
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
