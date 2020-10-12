// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package database

import (
	"errors"
)

var (
	// ErrNoVersionRecord is emitted when no version record exists.
	ErrNoVersionRecord = errors.New("no version record")

	// ErrNoPullRequestFound is emitted when no pull request matches.
	ErrNoPullRequestFound = errors.New("no pull request found")

	// ErrNoPullRequestReviewFound is emitted when no review matches.
	ErrNoPullRequestReviewFound = errors.New("no pull request review found")

	// ErrNoCommitFound is emitted when no commit matches.
	ErrNoCommitFound = errors.New("no commit found")

	// ErrWrongVersion is emitted when the version record does not
	// match the implementation version.
	ErrWrongVersion = errors.New("wrong version")

	// ErrShutdown is emitted when the cache is shutting down.
	ErrShutdown = errors.New("cache is shutting down")

	// ErrUserNotFound indicates that a user name was not found in the
	// database.
	ErrUserNotFound = errors.New("user not found")
)

// Database interface contains all the functions expected of any db
// implemention for github code stats.
type Database interface {
	// NewPullRequest creates a new pull request for the github code db.
	NewPullRequest(*PullRequest) error

	// UpdatePullRequest updates an existing pull request row.
	UpdatePullRequest(*PullRequest) error

	// PullRequestByID returns the pull request that matches the provided id.
	PullRequestByID(id string) (*PullRequest, error)

	// PullRequestsByURL returns all pull request entries matching the url.
	PullRequestsByURL(url string) ([]*PullRequest, error)

	// MergedPullRequestsByUserDates returns all merged pull requests that match the
	// username and is in between the start and end dates (in Unix).
	MergedPullRequestsByUserDates(username string, start int64, end int64) ([]*PullRequest, error)

	// UpdatedPullRequestsByUserDates returns all updated pull requests that match the
	// username and is in between the start and end dates (in Unix).
	UpdatedPullRequestsByUserDates(username string, start int64, end int64) ([]*PullRequest, error)

	// NewPullRequestReview creates a new entry for a pull request review.
	NewPullRequestReview(*PullRequestReview) error

	// UpdatePullRequestReview updates an exisiting entry for a pull request
	// review.
	UpdatePullRequestReview(*PullRequestReview) error

	// ReviewByID returns a pull request review with a matching ID.
	ReviewByID(id int64) (*PullRequestReview, error)

	// ReviewsByUserDates retrusn all reviews from the given user between
	// the dates provided.
	ReviewsByUserDates(user string, start int64, end int64) ([]PullRequestReview, error)

	// NewCommit creates a new entry for a pull request commit.
	NewCommit(*Commit) error

	// CommitBySHA returns a commit that matches the SHA.
	CommitBySHA(sha string) (*Commit, error)

	// CommitsByUserDates returns all commits that match the
	// username and is in between the start and end dates (in Unix).
	CommitsByUserDates(username string, start int64, end int64) ([]Commit, error)

	// Setup creates the database instance and prepares it for usage.
	Setup() error

	// Close performs cleanup of the backend.
	Close() error
}

// PullRequest contains all information pertaining to a specific PR.
type PullRequest struct {
	ID           string
	Repo         string
	Organization string
	User         string
	URL          string
	Number       int
	UpdatedAt    int64
	ClosedAt     int64
	MergedAt     int64
	Merged       bool
	State        string
	Additions    int
	Deletions    int
	MergedBy     string
}

// PullRequestReview contains any information about reviews that a user
// has submitted to a matching organization PR.
type PullRequestReview struct {
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

type Commit struct {
	SHA          string `json:"sha"`
	Repo         string `json:"repo"`
	Organization string `json:"organization"`
	Date         int64  `json:"date"`
	Author       string `json:"author"`
	Committer    string `json:"committer"`
	Message      string `json:"message"`
	URL          string `json:"url"`
	ParentSHA    string `json:"parentsha"`
	ParentURL    string `json:"parenturl"`
	Additons     int    `json:"additions"`
	Deletions    int    `json:"deletions"`
	Rebase       bool   `json:"rebase"`
}
