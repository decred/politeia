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
	return &database.PullRequestReview{
		PullRequestURL: prReview.PullRequestURL,
		Author:         prReview.Author,
		State:          prReview.State,
		SubmittedAt:    prReview.SubmittedAt,
		CommitID:       prReview.CommitID,
		ID:             prReview.ID,
		Repo:           prReview.Repo,
		Number:         prReview.Number,
	}
}

// EncodePullRequest encodes a database.PullRequest into a cockroachdb
// PullRequest.
func EncodePullRequest(dbPullRequest *database.PullRequest) PullRequest {
	return PullRequest{
		ID:           dbPullRequest.ID,
		URL:          dbPullRequest.URL,
		Repo:         dbPullRequest.Repo,
		Organization: dbPullRequest.Organization,
		Number:       dbPullRequest.Number,
		Author:       dbPullRequest.User,
		State:        dbPullRequest.State,
		UpdatedAt:    dbPullRequest.UpdatedAt,
		ClosedAt:     dbPullRequest.ClosedAt,
		MergedAt:     dbPullRequest.MergedAt,
		Merged:       dbPullRequest.Merged,
		Additions:    dbPullRequest.Additions,
		Deletions:    dbPullRequest.Deletions,
		MergedBy:     dbPullRequest.MergedBy,
	}
}

// DecodePullRequest decodes a cockroachdb PullRequest into a generic
// database.PullRequest
func DecodePullRequest(pr *PullRequest) *database.PullRequest {
	return &database.PullRequest{
		ID:           pr.ID,
		URL:          pr.URL,
		Repo:         pr.Repo,
		Organization: pr.Organization,
		Number:       pr.Number,
		User:         pr.Author,
		State:        pr.State,
		UpdatedAt:    pr.UpdatedAt,
		ClosedAt:     pr.ClosedAt,
		MergedAt:     pr.MergedAt,
		Merged:       pr.Merged,
		Additions:    pr.Additions,
		Deletions:    pr.Deletions,
		MergedBy:     pr.MergedBy,
	}
}

func convertMatchingReviewsToDatabaseReviews(matching []MatchingReviews) []database.PullRequestReview {
	reviews := make([]database.PullRequestReview, 0, len(matching))
	for _, match := range matching {
		reviews = append(reviews, database.PullRequestReview{
			PullRequestURL: match.PullRequestURL,
			ID:             match.ID,
			Author:         match.Author,
			State:          match.State,
			Repo:           match.Repo,
			SubmittedAt:    match.SubmittedAt,
			Additions:      match.Additions,
			Deletions:      match.Deletions,
		})
	}
	return reviews
}

func encodeCommit(dbCommit *database.Commit) Commit {
	return Commit{
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
		Additions:    dbCommit.Additions,
		Deletions:    dbCommit.Deletions,
	}
}

func decodeCommit(commit *Commit) *database.Commit {
	return &database.Commit{
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
		Additions:    commit.Additions,
		Deletions:    commit.Deletions,
	}
}
