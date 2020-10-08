// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package github

import (
	"strconv"
	"time"

	"github.com/decred/politeia/politeiawww/codetracker"
	"github.com/decred/politeia/politeiawww/codetracker/github/api"
	"github.com/decred/politeia/politeiawww/codetracker/github/database"
)

const githubPullURL = "https://github.com"

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
		pr := codetracker.PullRequestInformation{
			Repository: dbPR.Repo,
			Additions:  int64(dbPR.Additions),
			Deletions:  int64(dbPR.Deletions),
			Date:       time.Unix(dbPR.MergedAt, 0).Format(time.RFC1123),
			Number:     dbPR.Number,
			State:      dbPR.State,
		}
		prInfo = append(prInfo, pr)
	}
	return prInfo
}

func convertDBPullRequestReviewsToReviews(dbReviews []database.PullRequestReview) []codetracker.ReviewInformation {
	reviewInfo := make([]codetracker.ReviewInformation, 0, len(dbReviews))

	for _, dbReview := range dbReviews {
		review := codetracker.ReviewInformation{
			URL:        dbReview.PullRequestURL,
			State:      dbReview.State,
			Number:     dbReview.Number,
			Repository: dbReview.Repo,
			Additions:  dbReview.Additions,
			Deletions:  dbReview.Deletions,
		}
		reviewInfo = append(reviewInfo, review)
	}
	return reviewInfo
}
func convertCodeStatsToUserInformation(mergedPRs []*database.PullRequest, updatedPRs []*database.PullRequest, reviews []database.PullRequestReview) *codetracker.UserInformationResult {
	userInfo := &codetracker.UserInformationResult{}
	mergedPRInfo := convertDBPullRequestsToPullRequests(mergedPRs)
	updatedPRInfo := convertDBPullRequestsToPullRequests(updatedPRs)
	reviewInfo := convertDBPullRequestReviewsToReviews(reviews)

	userInfo.MergedPRs = mergedPRInfo
	userInfo.UpdatedPRs = updatedPRInfo
	userInfo.Reviews = reviewInfo
	return userInfo
}
