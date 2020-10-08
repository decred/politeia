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
		}
		prInfo = append(prInfo, pr)
	}
	return prInfo
}

func convertCodeStatsToUserInformation(mergedPRs []*database.PullRequest, updatedPRs []*database.PullRequest, reviews []database.PullRequestReview) *codetracker.UserInformationResult {
	repoStats := make([]codetracker.RepositoryInformation, 0, 1048) // PNOOMA
	userInfo := &codetracker.UserInformationResult{}
	mergedPRInfo := make([]codetracker.PullRequestInformation, 0, len(mergedPRs))
	updatedPRInfo := make([]codetracker.PullRequestInformation, 0, len(updatedPRs))
	reviewInfo := make([]codetracker.ReviewInformation, 0, len(reviews))
	for _, pr := range mergedPRs {
		repoFound := false
		for i, repoStat := range repoStats {
			if repoStat.Repository == pr.Repo {
				repoFound = true
				repoStat.PRs = append(repoStat.PRs, pr.URL)
				repoStat.MergedAdditions += int64(pr.Additions)
				repoStat.MergedDeletions += int64(pr.Deletions)
				repoStats[i] = repoStat
				break
			}
		}
		if !repoFound {
			repoStat := codetracker.RepositoryInformation{
				PRs:             []string{pr.URL},
				Repository:      pr.Repo,
				MergedAdditions: int64(pr.Additions),
				MergedDeletions: int64(pr.Deletions),
			}
			repoStats = append(repoStats, repoStat)
		}
		mergedPRInfo = append(mergedPRInfo, codetracker.PullRequestInformation{
			Repository: pr.Repo,
			URL:        pr.URL,
			Number:     pr.Number,
			Additions:  int64(pr.Additions),
			Deletions:  int64(pr.Deletions),
			Date:       time.Unix(pr.MergedAt, 0).String(),
			State:      pr.State,
		})

	}
	for _, review := range reviews {
		repoFound := false
		for i, repoStat := range repoStats {
			if repoStat.Repository == review.Repo {
				repoFound = true
				repoStat.ReviewAdditions += int64(review.Additions)
				repoStat.ReviewDeletions += int64(review.Deletions)
				repoStats[i] = repoStat
				break
			}
		}
		if !repoFound {
			repoStat := codetracker.RepositoryInformation{
				Repository:      review.Repo,
				ReviewAdditions: int64(review.Additions),
				ReviewDeletions: int64(review.Deletions),
			}
			repoStats = append(repoStats, repoStat)
		}
		reviewInfo = append(reviewInfo, codetracker.ReviewInformation{
			URL:        review.PullRequestURL,
			State:      review.State,
			Number:     review.Number,
			Repository: review.Repo,
			Additions:  review.Additions,
			Deletions:  review.Deletions,
		})
	}

	userInfo.RepoDetails = repoStats
	userInfo.MergedPRs = mergedPRInfo
	userInfo.UpdatedPRs = updatedPRInfo
	userInfo.Reviews = reviewInfo
	return userInfo
}
