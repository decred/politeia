// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package cockroachdb

import (
	"github.com/decred/politeia/politeiawww/codetracker/github/database"
)

// EncodePullRequestReview encodes a database.PullRequestReview into a
// cockroachdb PullRequestReview.
func EncodePullRequestReview(dbPullRequestReview *database.PullRequestReview) PullRequestReview {
	prReview := PullRequestReview{}
	prReview.Author = dbPullRequestReview.Author
	prReview.State = dbPullRequestReview.State
	prReview.SubmittedAt = dbPullRequestReview.SubmittedAt
	prReview.CommitID = dbPullRequestReview.CommitID
	prReview.ID = dbPullRequestReview.ID
	prReview.Number = dbPullRequestReview.Number
	prReview.Repo = dbPullRequestReview.Repo
	prReview.PullRequestURL = dbPullRequestReview.PullRequestURL

	return prReview
}

// DecodePullRequestReview decodes a cockroachdb PullRequestReview into a
// generic database.PullRequestReview
func DecodePullRequestReview(prReview *PullRequestReview) *database.PullRequestReview {
	dbPullRequestReview := &database.PullRequestReview{}
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

// EncodePullRequest encodes a database.PullRequest into a cockroachdb
// PullRequest.
func EncodePullRequest(dbPullRequest *database.PullRequest) PullRequest {
	pr := PullRequest{}
	pr.ID = dbPullRequest.ID
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

	return pr
}

// DecodePullRequest decodes a cockroachdb PullRequest into a generic
// database.PullRequest
func DecodePullRequest(pr *PullRequest) *database.PullRequest {
	dbPullRequest := &database.PullRequest{}
	dbPullRequest.ID = pr.ID
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

	return dbPullRequest
}

func convertMatchingReviewsToDatabaseReviews(matching []MatchingReviews) []database.PullRequestReview {
	reviews := make([]database.PullRequestReview, 0, len(matching))
	for _, match := range matching {
		review := database.PullRequestReview{
			PullRequestURL: match.PullRequestURL,
			ID:             match.ID,
			Author:         match.Author,
			State:          match.State,
			Repo:           match.Repo,
			SubmittedAt:    match.SubmittedAt,
			Additions:      match.Additions,
			Deletions:      match.Deletions,
		}
		reviews = append(reviews, review)
	}
	return reviews
}

func encodeCommit(dbCommit *database.Commit) Commit {
	commit := Commit{
		SHA:          dbCommit.SHA,
		URL:          dbCommit.URL,
		Repo:         dbCommit.Repo,
		Organization: dbCommit.Organization,
		Message:      dbCommit.Message,
		Date:         dbCommit.Date,
		Author:       dbCommit.Author,
		Committer:    dbCommit.Committer,
		ParentSHA:    dbCommit.ParentSHA,
		ParentURL:    dbCommit.ParentURL,
		Additons:     dbCommit.Additons,
		Deletions:    dbCommit.Deletions,
	}
	return commit
}

func decodeCommit(commit *Commit) *database.Commit {
	dbCommit := &database.Commit{
		SHA:          commit.SHA,
		URL:          commit.URL,
		Repo:         commit.Repo,
		Organization: commit.Organization,
		Message:      commit.Message,
		Date:         commit.Date,
		Author:       commit.Author,
		Committer:    commit.Committer,
		ParentSHA:    commit.ParentSHA,
		ParentURL:    commit.ParentURL,
		Additons:     commit.Additons,
		Deletions:    commit.Deletions,
	}
	return dbCommit
}
