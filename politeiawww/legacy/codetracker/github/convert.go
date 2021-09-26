// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package github

import (
	"strconv"
	"time"

	"github.com/decred/politeia/politeiawww/legacy/codetracker"
	"github.com/decred/politeia/politeiawww/legacy/codetracker/github/api"
	"github.com/decred/politeia/politeiawww/legacy/codetracker/github/database"
)

const githubPullURL = "https://github.com"

func convertAPICommitsToDbComits(apiCommits []*api.PullRequestCommit, org, repoName string) []*database.Commit {
	dbCommits := make([]*database.Commit, 0, len(apiCommits))
	for _, commit := range apiCommits {
		parentSHA := ""
		parentURL := ""
		if len(commit.Parents) > 0 {
			parentSHA = commit.Parents[0].SHA
			parentURL = commit.Parents[0].URL
		}
		dbCommits = append(dbCommits, &database.Commit{
			SHA:          commit.SHA,
			URL:          commit.URL,
			Message:      commit.Commit.Message,
			Author:       commit.Author.Login,
			Committer:    commit.Committer.Login,
			Date:         parseTime(commit.Commit.Author.Date).Unix(),
			Additions:    commit.Stats.Additions,
			Deletions:    commit.Stats.Deletions,
			ParentSHA:    parentSHA,
			ParentURL:    parentURL,
			Repo:         repoName,
			Organization: org,
		})
	}
	return dbCommits
}
func convertAPIPullRequestToDbPullRequest(apiPR *api.PullRequest, repoName, org string) (*database.PullRequest, error) {
	url := githubPullURL + "/" + org + "/" + repoName + "/pull/" +
		strconv.Itoa(apiPR.Number)
	dbPR := &database.PullRequest{
		ID:           url + apiPR.UpdatedAt,
		Repo:         repoName,
		Organization: org,
		User:         apiPR.User.Login,
		URL:          url,
		Number:       apiPR.Number,
		State:        apiPR.State,
		Additions:    apiPR.Additions,
		Deletions:    apiPR.Deletions,
	}
	if apiPR.MergedAt != "" {
		mergedAt, err := time.Parse(time.RFC3339, apiPR.MergedAt)
		if err != nil {
			return nil, err
		}
		dbPR.MergedAt = mergedAt.Unix()
	}
	if apiPR.UpdatedAt != "" {
		updatedAt, err := time.Parse(time.RFC3339, apiPR.UpdatedAt)
		if err != nil {
			return nil, err
		}
		dbPR.UpdatedAt = updatedAt.Unix()
	}
	return dbPR, nil
}

func convertAPIReviewsToDbReviews(apiReviews []api.PullRequestReview, repo string, prNumber int, url string) []database.PullRequestReview {
	dbReviews := make([]database.PullRequestReview, 0, len(apiReviews))
	for _, review := range apiReviews {
		dbReview := convertAPIReviewToDbReview(review)
		dbReview.Repo = repo
		dbReview.Number = prNumber
		dbReview.PullRequestURL = url
		dbReviews = append(dbReviews, dbReview)
	}
	return dbReviews
}

func convertAPIReviewToDbReview(apiReview api.PullRequestReview) database.PullRequestReview {
	dbReview := database.PullRequestReview{
		ID:          apiReview.ID,
		Author:      apiReview.User.Login,
		State:       apiReview.State,
		SubmittedAt: parseTime(apiReview.SubmittedAt).Unix(),
		CommitID:    apiReview.CommitID,
	}
	return dbReview
}

func convertDBPullRequestsToPullRequests(dbPRs []*database.PullRequest) []codetracker.PullRequestInformation {
	prInfo := make([]codetracker.PullRequestInformation, 0, len(dbPRs))
	for _, dbPR := range dbPRs {
		prInfo = append(prInfo, codetracker.PullRequestInformation{
			URL:        dbPR.URL,
			Repository: dbPR.Repo,
			Additions:  int64(dbPR.Additions),
			Deletions:  int64(dbPR.Deletions),
			Date:       time.Unix(dbPR.UpdatedAt, 0).Format(time.RFC1123),
			Number:     dbPR.Number,
			State:      dbPR.State,
		})
	}
	return prInfo
}

func convertDBPullRequestReviewsToReviews(dbReviews []database.PullRequestReview) []codetracker.ReviewInformation {
	reviewInfo := make([]codetracker.ReviewInformation, 0, len(dbReviews))
	for _, dbReview := range dbReviews {
		reviewInfo = append(reviewInfo, codetracker.ReviewInformation{
			URL:        dbReview.PullRequestURL,
			State:      dbReview.State,
			Number:     dbReview.Number,
			Repository: dbReview.Repo,
			Additions:  dbReview.Additions,
			Deletions:  dbReview.Deletions,
		})
	}
	return reviewInfo
}

func convertDBCommitsToCommits(dbCommits []database.Commit) []codetracker.CommitInformation {
	commitInfo := make([]codetracker.CommitInformation, 0, len(dbCommits))
	for _, dbCommit := range dbCommits {
		commitInfo = append(commitInfo, codetracker.CommitInformation{
			SHA:        dbCommit.SHA,
			URL:        dbCommit.URL,
			Repository: dbCommit.Repo,
			Additions:  dbCommit.Additions,
			Deletions:  dbCommit.Deletions,
			Date:       dbCommit.Date,
		})
	}
	return commitInfo
}

func convertCodeStatsToUserInformation(mergedPRs []*database.PullRequest, updatedPRs []*database.PullRequest, reviews []database.PullRequestReview, commits []database.Commit) *codetracker.UserInformationResult {
	userInfo := &codetracker.UserInformationResult{}
	mergedPRInfo := convertDBPullRequestsToPullRequests(mergedPRs)
	updatedPRInfo := convertDBPullRequestsToPullRequests(updatedPRs)
	reviewInfo := convertDBPullRequestReviewsToReviews(reviews)
	commitInfo := convertDBCommitsToCommits(commits)

	userInfo.MergedPRs = mergedPRInfo
	userInfo.UpdatedPRs = updatedPRInfo
	userInfo.Reviews = reviewInfo
	userInfo.Commits = commitInfo
	return userInfo
}
