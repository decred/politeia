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
	tableNameVersions     = "versions"
	tableNameOrganization = "organizations"
	tableNamePullRequest  = "pullrequests"
	tableNameCommits      = "commits"
	tableNameReviews      = "reviews"

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
func (c *cockroachdb) PullRequestByURL(url string) (*database.PullRequest, error) {
	log.Debugf("PullRequestByURL: %v", url)

	pr := PullRequest{
		URL: url,
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

// PullRequestsByUserDates takes a username, start and end date and returns
// pull requeests that match those criteria.
func (c *cockroachdb) PullRequestsByUserDates(username string, start, end int64) ([]*database.PullRequest, error) {
	log.Debugf("PullRequestsByUserDates: %v %v", time.Unix(start, 0),
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

// ReviewsByUserDates takes username, start and end date and returns all reviews
// that match the provided criteria.
func (c *cockroachdb) ReviewsByUserDates(username string, start, end int64) ([]database.PullRequestReview, error) {
	log.Debugf("ReviewsByUserDates: %v %v", time.Unix(start, 0),
		time.Unix(end, 0))

	// Get all Reviews from a user between the given dates.
	reviews := make([]PullRequestReview, 0, 1024) // PNOOMA
	err := c.recordsdb.
		Table(tableNameReviews).
		Where("author = ? AND state = ? AND "+
			"submitted_at BETWEEN ? AND ?",
			username,
			"APPROVED",
			start,
			end).
		Find(&reviews).
		Error
	if err != nil {
		return nil, err
	}
	dbReviews := make([]database.PullRequestReview, 0, len(reviews))
	for _, vv := range reviews {
		pr := PullRequest{}

		err := c.recordsdb.
			Table(tableNamePullRequest).
			Where("repo = ? AND number = ?",
				vv.Repo,
				vv.Number).
			Find(&pr).
			Error
		if err != nil {
			log.Errorf("pull request %v %v for review not found", vv.Repo,
				vv.Number)
			continue
		}
		dbReview := DecodePullRequestReview(&vv)
		dbReview.Additions = pr.Additions
		dbReview.Deletions = pr.Deletions
		dbReviews = append(dbReviews, dbReview)
	}
	return dbReviews, nil
}

// Return all users that have any merged PRs in the provided range.
func (c *cockroachdb) AllUsersByDates(start, end int64) ([]string, error) {
	log.Debugf("AllUsersByDates: %v %v", time.Unix(start, 0),
		time.Unix(end, 0))

	type Users struct {
		User string
	}
	// Get all PRs from a user between the given dates.
	usernames := make([]Users, 0, 1024) // PNOOMA
	err := c.recordsdb.
		Table(tableNamePullRequest).
		Where("DISTINCT AND "+
			"merged_at BETWEEN ? AND ?",
			start,
			end).
		Find(&usernames).
		Error
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(usernames))
	for _, vv := range usernames {
		names = append(names, vv.User)
	}
	return names, nil
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
	if !tx.HasTable(tableNameCommits) {
		err := tx.CreateTable(&Commit{}).Error
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

	return nil

}

// Setup calls the tables creation function to ensure the database is prepared for use.
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
