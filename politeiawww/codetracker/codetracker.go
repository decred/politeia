// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package codetracker

// CodeTracker interface for getting Code Stats from a git based code tracking
// site (Github/Gitlab etc).
type CodeTracker interface {
	// Update updates the code stats for a (organization, repo)
	Update(org, repo string) error

	// UserInfo returns pull request, review and commit information about
	// a given user over a given start and stop time.
	UserInfo(org, username string, start, end int) (*UserInformationResult, error)
}

// UserInformationResult models the data from the userinformation command.
type UserInformationResult struct {
	User         string                   `json:"user"`
	Organization string                   `json:"organization"`
	PRs          []PullRequestInformation `json:"prs"`
	RepoDetails  []RepositoryInformation  `json:"repodetails"`
	Reviews      []ReviewInformation      `json:"reviews"`
	Year         int                      `json:"year"`
	Month        int                      `json:"month"`
}

type RepositoryInformation struct {
	PRs             []string `json:"prs"`
	Reviews         []string `json:"reviews"`
	Repository      string   `json:"repo"`
	CommitAdditions int64    `json:"commitadditions"`
	CommitDeletions int64    `json:"commitdeletions"`
	MergeAdditions  int64    `json:"mergeadditions"`
	MergeDeletions  int64    `json:"mergedeletions"`
	ReviewAdditions int64    `json:"reviewadditions"`
	ReviewDeletions int64    `json:"reviewdeletions"`
}

type PullRequestInformation struct {
	Repository string `json:"repo"`
	URL        string `json:"url"`
	Number     int    `json:"number"`
	Additions  int64  `json:"additions"`
	Deletions  int64  `json:"deletions"`
	Date       string `json:"date"`
	State      string `json:"state"`
}

type ReviewInformation struct {
	Repository string `json:"repo"`
	URL        string `json:"url"`
	Number     int    `json:"number"`
	Additions  int    `json:"additions"`
	Deletions  int    `json:"deletions"`
	Date       string `json:"date"`
	State      string `json:"state"`
}
