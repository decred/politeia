// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

// Version describes the version of a record or plugin that the database is
// currently using.
type Version struct {
	ID        string `gorm:"primary_key"` // Primary key
	Version   string `gorm:"not null"`    // Version
	Timestamp int64  `gorm:"not null"`    // UNIX timestamp of record creation
}

// TableName returns the table name of the versions table.
func (Version) TableName() string {
	return tableNameVersions
}

// PullRequest table has all of the information for a given PullRequest,
// this also includes its commits and reviews.
type PullRequest struct {
	ID           string `gorm:"primary_key"`
	Repo         string `gorm:"not null"`
	Organization string `gorm:"not null"`
	URL          string `gorm:"not null"`
	Number       int    `gorm:"not null"`
	Author       string `gorm:"not null"`
	UpdatedAt    int64  `gorm:"not null"`
	ClosedAt     int64  `gorm:"not null"`
	MergedAt     int64  `gorm:"not null"`
	Merged       bool   `gorm:"not null"`
	State        string `gorm:"not null"`
	Additions    int    `gorm:"not null"`
	Deletions    int    `gorm:"not null"`
	MergedBy     string `gorm:"not null"`
}

// TableName returns the table name of the pull requests table.
func (PullRequest) TableName() string {
	return tableNamePullRequest
}

// PullRequestReview contains all of the information about reviews of a given
// pull request.
type PullRequestReview struct {
	PullRequestURL string `gorm:"not null"`
	ID             int64  `gorm:"primary_key"`
	Author         string `gorm:"not null"`
	State          string `gorm:"not null"`
	SubmittedAt    int64  `gorm:"not null"`
	CommitID       string `gorm:"not null"`
	Repo           string `gorm:"not null"`
	Number         int    `gorm:"not null"`
}

// TableName returns the table name of the pull requests review table.
func (PullRequestReview) TableName() string {
	return tableNameReviews
}

type Commit struct {
	SHA          string `gorm:"primary_key"`
	Repo         string `gorm:"repo"`
	Organization string `gorm:"organization"`
	Date         int64  `gorm:"not null"`
	Author       string `gorm:"not null"`
	Committer    string `gorm:"not null"`
	Message      string `gorm:"not null"`
	URL          string `gorm:"not null"`
	ParentSHA    string `gorm:"not null"`
	ParentURL    string `gorm:"not null"`
	Additons     int    `gorm:"not null"`
	Deletions    int    `gorm:"not null"`
	Rebase       bool   `gorm:"not null"`
}

// TableName returns the table name of the commits table.
func (Commit) TableName() string {
	return tableNameCommits
}
