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

	// ErrWrongVersion is emitted when the version record does not
	// match the implementation version.
	ErrWrongVersion = errors.New("wrong version")

	// ErrShutdown is emitted when the cache is shutting down.
	ErrShutdown = errors.New("cache is shutting down")

	// ErrUserNotFound indicates that a user name was not found in the
	// database.
	ErrUserNotFound = errors.New("user not found")
)

// Database interface that is required by the web server.
type Database interface {
	NewPullRequest(*PullRequest) error    // Create new pull request
	UpdatePullRequest(*PullRequest) error // Update exisiting pull request
	PullRequestByURL(string) (*PullRequest, error)
	PullRequestsByUserDates(string, int64, int64) ([]*PullRequest, error) // Retrieve all pull requests that match username between dates

	AllUsersByDates(int64, int64) ([]string, error)

	NewPullRequestReview(*PullRequestReview) error                                       // Create new pull request review
	UpdatePullRequestReview(*PullRequestReview) error                                    // Update existing pull request review
	ReviewsByUserDates(user string, start int64, end int64) ([]PullRequestReview, error) // Retrieve all reviews that match username between dates

	Setup() error

	// Close performs cleanup of the backend.
	Close() error
}

// PullRequest contains all information pertaining to a specific PR.
type PullRequest struct {
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

	Reviews []PullRequestReview
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
