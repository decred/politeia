// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"fmt"
	"net/url"
	"path/filepath"
	"sync"
	"time"

	"github.com/decred/politeia/politeiawww/codetracker/github/database"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

const (
	cacheID   = "ghtracker"
	ghVersion = "1"

	// Database table names
	tableNameVersions    = "versions"
	tableNamePullRequest = "pullrequests"
	tableNameCommits     = "commits"
	tableNameReviews     = "reviews"

	userPoliteiawww = "politeiawww" // cmsdb user (read/write access)
)

// cockroachdb implements the cache interface.
type cockroachdb struct {
	sync.RWMutex
	shutdown  bool     // Backend is shutdown
	recordsdb *gorm.DB // Database context
}

// Create new Pull Request.
//
// NewPullRequest satisfies the database interface.
func (c *cockroachdb) NewPullRequest(dbPullRequest *database.PullRequest) error {
	pr := EncodePullRequest(dbPullRequest)

	log.Debugf("NewPullRequest: %v", pr.URL)
	return c.recordsdb.Create(&pr).Error
}

// Update existing pr.
//
// UpdatePullRequest satisfies the database interface.
func (c *cockroachdb) UpdatePullRequest(dbPullRequest *database.PullRequest) error {
	pr := EncodePullRequest(dbPullRequest)

	log.Debugf("UpdatePullRequest: %v", pr.URL)
	return c.recordsdb.Save(&pr).Error
}

// PullRequestByURL return a PullRequest by its URL.
func (c *cockroachdb) PullRequestByID(id string) (*database.PullRequest, error) {
	log.Debugf("PullRequestByID: %v", id)

	pr := PullRequest{
		ID: id,
	}
	err := c.recordsdb.
		Find(&pr).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = database.ErrNoPullRequestFound
		}
		return nil, err
	}

	return DecodePullRequest(&pr), nil
}

// MergedPullRequestsByUserDates takes a username, start and end date and
// returns merged pull requests that match those criteria.
func (c *cockroachdb) MergedPullRequestsByUserDates(username string, start, end int64) ([]*database.PullRequest, error) {
	log.Debugf("MergedPullRequestsByUserDates: %v %v", time.Unix(start, 0),
		time.Unix(end, 0))

	// Get all PRs from a user between the given dates.
	prs := make([]PullRequest, 0, 1024) // PNOOMA
	err := c.recordsdb.
		Where("author = ? AND "+
			"merged_at BETWEEN ? AND ?",
			username,
			start,
			end).
		Find(&prs).
		Error
	if err != nil {
		return nil, err
	}
	dbPRs := make([]*database.PullRequest, 0, len(prs))
	for _, vv := range prs {
		dbPRs = append(dbPRs, DecodePullRequest(&vv))
	}
	return dbPRs, nil
}

// UpdatedPullRequestsByUserDates takes a username, start and end date and
// returns updated pull requests that match those criteria.
func (c *cockroachdb) UpdatedPullRequestsByUserDates(username string, start, end int64) ([]*database.PullRequest, error) {
	log.Debugf("UpdatedPullRequestsByUserDates: %v %v", time.Unix(start, 0),
		time.Unix(end, 0))

	// Select the most recent pullrequests (by url) that match author and are
	// between start and end.
	query := `
		SELECT * FROM pullrequests 
		WHERE author = $1 AND updated_at IN 
		(SELECT 
			MAX(updated_at) 
			FROM pullrequests 
			WHERE updated_at BETWEEN $2 AND $3 
			GROUP BY url
		)
		`
	rows, err := c.recordsdb.Raw(query, username, start, end).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	prs := make([]PullRequest, 0, 1024) // PNOOMA
	for rows.Next() {
		var pr PullRequest
		err := c.recordsdb.ScanRows(rows, &pr)
		if err != nil {
			return nil, err
		}
		prs = append(prs, pr)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	dbPRs := make([]*database.PullRequest, 0, len(prs))
	for _, pr := range prs {
		dbPRs = append(dbPRs, DecodePullRequest(&pr))
	}
	return dbPRs, nil
}

func (c *cockroachdb) PullRequestsByURL(url string) ([]*database.PullRequest, error) {
	urlPRs := make([]PullRequest, 0, 1024) // PNOOMA
	err := c.recordsdb.
		Where("url = ?",
			url).
		Find(&urlPRs).
		Error
	if err != nil {
		return nil, err
	}
	dbPRs := make([]*database.PullRequest, 0, len(urlPRs))
	for _, pr := range urlPRs {
		dbPRs = append(dbPRs, DecodePullRequest(&pr))
	}
	return dbPRs, nil
}

type MatchingReviews struct {
	PullRequestURL string
	ID             int64
	Author         string
	State          string
	SubmittedAt    int64
	CommitID       string
	Repo           string
	Number         int
	Additions      int
	Deletions      int
}

// ReviewsByUserDates takes username, start and end date and returns all reviews
// that match the provided criteria.
func (c *cockroachdb) ReviewsByUserDates(username string, start, end int64) ([]database.PullRequestReview, error) {
	log.Debugf("ReviewsByUserDates: %v %v", time.Unix(start, 0),
		time.Unix(end, 0))

	// Get all Reviews from a user between the given dates.
	query := `
    SELECT 
      reviews.pull_request_url,
      reviews.id,
      reviews.author,
      reviews.state,
      reviews.submitted_at,
      reviews.commit_id,
      reviews.repo,
      reviews.number,
      pullrequests.additions,
      pullrequests.deletions
    FROM reviews
	INNER JOIN pullrequests
      ON pullrequests.url = reviews.pull_request_url
    WHERE reviews.author = $1 AND reviews.state = $2 AND 
	  reviews.submitted_at BETWEEN $3 AND $4`

	rows, err := c.recordsdb.Raw(query, username, "APPROVED", start, end).Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	matching := make([]MatchingReviews, 0, 1024)
	for rows.Next() {
		var i MatchingReviews
		err := c.recordsdb.ScanRows(rows, &i)
		if err != nil {
			return nil, err
		}
		matching = append(matching, i)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	return convertMatchingReviewsToDatabaseReviews(matching), nil
}

// Create new review.
//
// NewPullRequestReview satisfies the database interface.
func (c *cockroachdb) NewPullRequestReview(dbPullRequestReview *database.PullRequestReview) error {
	pr := EncodePullRequestReview(dbPullRequestReview)

	log.Debugf("NewPullRequestReview: %v", pr.CommitID)
	return c.recordsdb.Create(&pr).Error
}

// Update existing review.
//
// UpdatePullRequestReview satisfies the database interface.
func (c *cockroachdb) UpdatePullRequestReview(dbPullRequestReview *database.PullRequestReview) error {
	pr := EncodePullRequestReview(dbPullRequestReview)

	log.Debugf("UpdatePullRequestReview: %v", pr.CommitID)
	return c.recordsdb.Save(&pr).Error
}

// This function must be called within a transaction.
func createGHTables(tx *gorm.DB) error {
	log.Infof("createGHTables")

	// Create cms tables
	if !tx.HasTable(tableNamePullRequest) {
		err := tx.CreateTable(&PullRequest{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableNameReviews) {
		err := tx.CreateTable(&PullRequestReview{}).Error
		if err != nil {
			return err
		}
	}
	if !tx.HasTable(tableNameCommits) {
		err := tx.CreateTable(&Commit{}).Error
		if err != nil {
			return err
		}
	}

	return nil

}

// ReviewByID returns a review given the provided id.
func (c *cockroachdb) ReviewByID(id int64) (*database.PullRequestReview, error) {
	log.Debugf("ReviewByID: %v", id)

	review := PullRequestReview{
		ID: id,
	}
	err := c.recordsdb.
		Find(&review).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = database.ErrNoPullRequestReviewFound
		}
		return nil, err
	}

	return DecodePullRequestReview(&review), nil
}

// Create new commit.
//
// NewCommit satisfies the database interface.
func (c *cockroachdb) NewCommit(dbCommit *database.Commit) error {
	commit := encodeCommit(dbCommit)

	log.Debugf("NewCommit: %v", commit.SHA)
	return c.recordsdb.Create(&commit).Error
}

// CommitBySHA returns a commit given the provided hash.
func (c *cockroachdb) CommitBySHA(sha string) (*database.Commit, error) {
	log.Debugf("CommitBySHA: %v", sha)

	commit := Commit{
		SHA: sha,
	}
	err := c.recordsdb.
		Find(&commit).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			err = database.ErrNoCommitFound
		}
		return nil, err
	}

	return decodeCommit(&commit), nil
}

// CommitsByUserDates takes a username, start and end date and
// returns commits that match those criteria.
func (c *cockroachdb) CommitsByUserDates(username string, start, end int64) ([]database.Commit, error) {
	log.Debugf("CommitsByUserDates: %v %v", time.Unix(start, 0),
		time.Unix(end, 0))

	// Get all commits from a user between the given dates.
	commits := make([]Commit, 0, 1024) // PNOOMA
	err := c.recordsdb.
		Where("author = ? AND "+
			"date BETWEEN ? AND ?",
			username,
			start,
			end).
		Find(&commits).
		Error
	if err != nil {
		return nil, err
	}
	dbCommits := make([]database.Commit, 0, len(commits))
	for _, vv := range commits {
		dbCommits = append(dbCommits, *decodeCommit(&vv))
	}
	return dbCommits, nil
}

// Setup calls the tables creation function to ensure the database is prepared
// for use.
func (c *cockroachdb) Setup() error {
	tx := c.recordsdb.Begin()
	err := createGHTables(tx)
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

func buildQueryString(user, rootCert, cert, key string) string {
	v := url.Values{}
	v.Set("sslmode", "require")
	v.Set("sslrootcert", filepath.Clean(rootCert))
	v.Set("sslcert", filepath.Join(cert))
	v.Set("sslkey", filepath.Join(key))
	return v.Encode()
}

// New returns a new cockroachdb context that contains a connection to the
// specified database that was made using the politeiawww user and the passed
// in certificates.
func New(host, rootCert, cert, key string) (*cockroachdb, error) {
	log.Tracef("New: %v %v %v %v %v", host, rootCert, cert, key)

	// Connect to database
	dbName := cacheID
	h := "postgresql://" + userPoliteiawww + "@" + host + "/" + dbName
	u, err := url.Parse(h)
	if err != nil {
		return nil, fmt.Errorf("parse url '%v': %v", h, err)
	}

	qs := buildQueryString(u.User.String(), rootCert, cert, key)
	addr := u.String() + "?" + qs
	db, err := gorm.Open("postgres", addr)
	if err != nil {
		return nil, fmt.Errorf("connect to database '%v': %v", addr, err)
	}

	// Create context
	c := &cockroachdb{
		recordsdb: db,
	}

	// Disable gorm logging. This prevents duplicate errors from
	// being printed since we handle errors manually.
	c.recordsdb.LogMode(false)

	// Disable automatic table name pluralization. We set table
	// names manually.
	c.recordsdb.SingularTable(true)
	return c, err
}

// Close satisfies the database interface.
func (c *cockroachdb) Close() error {
	return c.recordsdb.Close()
}
