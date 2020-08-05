// Copyright (c) 2017-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"github.com/decred/politeia/politeiawww/codetracker/github/database"
)

// EncodeCommit encodes a database.Commit into a cockroachdb Commit.
func EncodeCommit(dbCommit *database.Commit) Commit {
	commit := Commit{}
	commit.URL = dbCommit.URL
	commit.SHA = dbCommit.SHA
	commit.Message = dbCommit.Message
	commit.Author = dbCommit.Author
	commit.Committer = dbCommit.Committer

	return commit
}

// DecodeCommit decodes a cockroachdb Commit into a generic database.Commit
func DecodeCommit(commit *Commit) database.Commit {
	dbCommit := database.Commit{}
	dbCommit.URL = commit.URL
	dbCommit.SHA = commit.SHA
	dbCommit.Message = commit.Message
	dbCommit.Author = commit.Author
	dbCommit.Committer = commit.Committer

	return dbCommit
}

// EncodePullRequestReview encodes a database.PullRequestReview into a cockroachdb PullRequestReview.
func EncodePullRequestReview(dbPullRequestReview *database.PullRequestReview) PullRequestReview {
	prReview := PullRequestReview{}
	prReview.Author = dbPullRequestReview.Author
	prReview.State = dbPullRequestReview.State
	prReview.SubmittedAt = dbPullRequestReview.SubmittedAt
	prReview.CommitID = dbPullRequestReview.CommitID
	prReview.ID = dbPullRequestReview.ID
	prReview.Number = dbPullRequestReview.Number
	prReview.Repo = dbPullRequestReview.Repo

	return prReview
}

// DecodePullRequestReview decodes a cockroachdb PullRequestReview into a generic database.PullRequestReview
func DecodePullRequestReview(prReview *PullRequestReview) database.PullRequestReview {
	dbPullRequestReview := database.PullRequestReview{}
	dbPullRequestReview.PullRequestURL = prReview.PullRequestURL
	dbPullRequestReview.Author = prReview.Author
	dbPullRequestReview.State = prReview.State
	dbPullRequestReview.SubmittedAt = prReview.SubmittedAt
	dbPullRequestReview.CommitID = prReview.CommitID
	dbPullRequestReview.ID = prReview.ID
	dbPullRequestReview.Repo = prReview.Repo
	dbPullRequestReview.Number = prReview.Number

	return dbPullRequestReview
}

// EncodePullRequest encodes a database.PullRequest into a cockroachdb PullRequest.
func EncodePullRequest(dbPullRequest *database.PullRequest) PullRequest {
	pr := PullRequest{}
	pr.URL = dbPullRequest.URL
	pr.Repo = dbPullRequest.Repo
	pr.Organization = dbPullRequest.Organization
	pr.Number = dbPullRequest.Number
	pr.Author = dbPullRequest.User
	pr.State = dbPullRequest.State
	pr.UpdatedAt = dbPullRequest.UpdatedAt
	pr.ClosedAt = dbPullRequest.ClosedAt
	pr.MergedAt = dbPullRequest.MergedAt
	pr.Merged = dbPullRequest.Merged
	pr.Additions = dbPullRequest.Additions
	pr.Deletions = dbPullRequest.Deletions
	pr.MergedBy = dbPullRequest.MergedBy

	commits := make([]Commit, 0, len(dbPullRequest.Commits))
	for _, dbCommit := range dbPullRequest.Commits {
		commits = append(commits, EncodeCommit(&dbCommit))
	}

	reviews := make([]PullRequestReview, 0, len(dbPullRequest.Reviews))
	for _, dbReview := range dbPullRequest.Reviews {
		reviews = append(reviews, EncodePullRequestReview(&dbReview))
	}
	pr.Reviews = reviews
	pr.Commits = commits
	return pr
}

// DecodePullRequest decodes a cockroachdb PullRequest into a generic database.PullRequest
func DecodePullRequest(pr *PullRequest) *database.PullRequest {
	dbPullRequest := &database.PullRequest{}
	dbPullRequest.URL = pr.URL
	dbPullRequest.Repo = pr.Repo
	dbPullRequest.Organization = pr.Organization
	dbPullRequest.Number = pr.Number
	dbPullRequest.User = pr.Author
	dbPullRequest.State = pr.State
	dbPullRequest.UpdatedAt = pr.UpdatedAt
	dbPullRequest.ClosedAt = pr.ClosedAt
	dbPullRequest.MergedAt = pr.MergedAt
	dbPullRequest.Merged = pr.Merged
	dbPullRequest.Additions = pr.Additions
	dbPullRequest.Deletions = pr.Deletions
	dbPullRequest.MergedBy = pr.MergedBy

	dbCommits := make([]database.Commit, 0, len(pr.Commits))
	for _, commit := range pr.Commits {
		dbCommits = append(dbCommits, DecodeCommit(&commit))
	}

	dbReviews := make([]database.PullRequestReview, 0, len(pr.Reviews))
	for _, review := range pr.Reviews {
		dbReviews = append(dbReviews, DecodePullRequestReview(&review))
	}
	dbPullRequest.Reviews = dbReviews
	dbPullRequest.Commits = dbCommits

	return dbPullRequest
}
