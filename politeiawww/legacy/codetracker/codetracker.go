// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package codetracker

// CodeTracker interface for getting Code Stats from a git based code tracking
// site (Github/Gitlab etc).
type CodeTracker interface {
	// Update updates the code stats for a (organization, repos, start end date)
	Update(repos []string, start, end int64)

	// UserInfo returns pull request, review and commit information about
	// a given user over a given start and stop time.
	UserInfo(username string, start, end int) (*UserInformationResult, error)
}

// UserInformationResult models the data from the userinformation command.
type UserInformationResult struct {
	User       string                   `json:"user"`
	MergedPRs  []PullRequestInformation `json:"mergedprs"`
	UpdatedPRs []PullRequestInformation `json:"updatedprs"`
	Commits    []CommitInformation      `json:"commits"`
	Reviews    []ReviewInformation      `json:"reviews"`
	Year       int                      `json:"year"`
	Month      int                      `json:"month"`
}

// PullRequestInformation contains all the specific details of pull request.
type PullRequestInformation struct {
	Repository string `json:"repository"`
	URL        string `json:"url"`
	Number     int    `json:"number"`
	Additions  int64  `json:"additions"`
	Deletions  int64  `json:"deletions"`
	Date       string `json:"date"`
	State      string `json:"state"`
}

// ReviewInformation contains all the details of a review of a pull request.
type ReviewInformation struct {
	Repository string `json:"repository"`
	URL        string `json:"url"`
	Number     int    `json:"number"`
	Additions  int    `json:"additions"`
	Deletions  int    `json:"deletions"`
	Date       string `json:"date"`
	State      string `json:"state"`
}

// CommitInformation contains all the details of a review of a pull request.
type CommitInformation struct {
	Repository string `json:"repository"`
	URL        string `json:"url"`
	SHA        string `json:"sha"`
	Additions  int    `json:"additions"`
	Deletions  int    `json:"deletions"`
	Date       int64  `json:"date"`
}
