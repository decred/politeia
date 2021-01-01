// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package api

// Author has basic information about the creator of a commit.
type Author struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Date  string `json:"date"`
}

// Commit holds basic information about a given commit, but no details
// about the actual changes.
type Commit struct {
	Author    Author `json:"author"`
	Committer Author `json:"committer"`
	Message   string `json:"message"`
}

// CommitParent has information about a commit's parent commit.
type CommitParent struct {
	SHA string `json:"sha"`
	URL string `json:"url"`
}

// CommitStats contains basic LOC information about a given commit.
type CommitStats struct {
	Additions int `json:"additions"`
	Deletions int `json:"deletions"`
	Total     int `json:"total"`
}

// PullRequestCommit contains information about commits underneath a given
// Pull request.
type PullRequestCommit struct {
	SHA       string         `json:"sha"`
	URL       string         `json:"url"`
	Parents   []CommitParent `json:"parents"`
	Stats     CommitStats    `json:"stats"`
	Commit    Commit         `json:"commit"`
	Author    User           `json:"author"`
	Committer User           `json:"committer"`

	// local change
	Discarded bool `json:"discarded"`
}

// PullsRequest contains all high level information returned from the
// PullsRequest request.
type PullsRequest struct {
	URL            string `json:"url"`
	Number         int    `json:"number"`
	State          string `json:"state"`
	Title          string `json:"title"`
	User           User   `json:"user"`
	UpdatedAt      string `json:"updated_at"`
	MergedAt       string `json:"merged_at"`
	MergeCommitSHA string `json:"merge_commit_sha"`
	CommitsURL     string `json:"commits_url"`
}

// PullRequest contains all the information about a submitted pull request.
type PullRequest struct {
	URL       string `json:"url"`
	Number    int    `json:"number"`
	User      User   `json:"user"`
	UpdatedAt string `json:"updated_at"`
	ClosedAt  string `json:"closed_at"`
	MergedAt  string `json:"merged_at"`
	Merged    bool   `json:"merged"`
	State     string `json:"state"`
	Additions int    `json:"additions"`
	Deletions int    `json:"deletions"`
	MergedBy  User   `json:"merged_by"`
}

// RateLimitRule has the limit, the number of requests remaining and the
// time to reset.
type RateLimitRule struct {
	Limit     int   `json:"limit"`
	Remaining int   `json:"remaining"`
	Reset     int64 `json:"reset"`
}

// RateLimitResource contains various RateLimitRule information.
type RateLimitResource struct {
	Core                RateLimitRule `json:"core"`
	Search              RateLimitRule `json:"search"`
	GraphQL             RateLimitRule `json:"graphql"`
	IntegrationManifest RateLimitRule `json:"integration_manifest"`
}

// RateLimit contains resource and rate information that is used to
// determine whether or not to limit request submission.
type RateLimit struct {
	Resources RateLimitResource `json:"resources"`
	Rate      RateLimitRule     `json:"rate"`
}

// Repository contains all the information of a repo underneath an organization.
type Repository struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Private  bool   `json:"private"`
	Owner    User   `json:"owner"`
	Fork     bool   `json:"fork"`
	URL      string `json:"url"`
}

// PullRequestReview contains information about any review that has been
// submitted for a given pull request.
type PullRequestReview struct {
	ID          int64  `json:"id"`
	User        User   `json:"user"`
	State       string `json:"state"`
	SubmittedAt string `json:"submitted_at"`
	CommitID    string `json:"commit_id"`
}

// User contains all the information about a given User connected to a
// Pull Request, Review or Commit.
type User struct {
	ID        int64  `json:"id"`
	NodeID    string `json:"node_id"`
	Login     string `json:"login"`
	URL       string `json:"url"`
	HTMLURL   string `json:"htmlurl"`
	Type      string `json:"type"`
	SiteAdmin bool   `json:"site_admin"`
}
