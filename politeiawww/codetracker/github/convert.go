// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package github

import (
	"strconv"
	"time"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	"github.com/decred/politeia/politeiawww/codetracker/github/api"
	"github.com/decred/politeia/politeiawww/codetracker/github/database"
)

const githubPullURL = "https://github.com"

func convertAPIPullRequestToDbPullRequest(apiPR *api.PullRequest, repo api.Repository, org string) (*database.PullRequest, error) {
	url := githubPullURL + "/" + org + "/" + repo.Name + "/pull/" + strconv.Itoa(apiPR.Number)
	dbPR := &database.PullRequest{
		Repo:         repo.Name,
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

func convertAPICommitsToDbCommits(apiCommits []api.PullRequestCommit) []database.Commit {
	dbCommits := make([]database.Commit, 0, len(apiCommits))
	for _, commit := range apiCommits {
		dbCommit := convertAPICommitToDbCommit(commit)
		dbCommits = append(dbCommits, dbCommit)
	}
	return dbCommits
}

func convertAPICommitToDbCommit(apiCommit api.PullRequestCommit) database.Commit {
	dbCommit := database.Commit{
		SHA:       apiCommit.SHA,
		URL:       apiCommit.URL,
		Message:   apiCommit.Commit.Message,
		Author:    apiCommit.Author.Login,
		Committer: apiCommit.Committer.Login,
		Additions: apiCommit.Stats.Additions,
		Deletions: apiCommit.Stats.Deletions,
	}
	return dbCommit
}

func convertAPIReviewsToDbReviews(apiReviews []api.PullRequestReview, repo string, prNumber int) []database.PullRequestReview {
	dbReviews := make([]database.PullRequestReview, 0, len(apiReviews))
	for _, review := range apiReviews {
		dbReview := convertAPIReviewToDbReview(review)
		dbReview.Repo = repo
		dbReview.Number = prNumber
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

func convertDBPullRequestsToPullRequests(dbPRs []*database.PullRequest) []cms.PullRequestInformation {
	prInfo := make([]cms.PullRequestInformation, 0, len(dbPRs))

	for _, dbPR := range dbPRs {
		pr := cms.PullRequestInformation{
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

func convertPRsandReviewsToUserInformation(prs []*database.PullRequest, reviews []database.PullRequestReview) *cms.UserInformationResult {
	repoStats := make([]cms.RepositoryInformation, 0, 1048) // PNOOMA
	userInfo := &cms.UserInformationResult{}
	prInfo := make([]cms.PullRequestInformation, 0, len(prs))
	reviewInfo := make([]cms.ReviewInformation, 0, len(reviews))
	for _, pr := range prs {
		repoFound := false
		for i, repoStat := range repoStats {
			if repoStat.Repository == pr.Repo {
				repoFound = true
				repoStat.PRs = append(repoStat.PRs, pr.URL)
				repoStat.MergeAdditions += int64(pr.Additions)
				repoStat.MergeDeletions += int64(pr.Deletions)
				repoStats[i] = repoStat
				break
			}
		}
		if !repoFound {
			repoStat := cms.RepositoryInformation{
				PRs:            []string{pr.URL},
				Repository:     pr.Repo,
				MergeAdditions: int64(pr.Additions),
				MergeDeletions: int64(pr.Deletions),
			}
			repoStats = append(repoStats, repoStat)
		}
		prInfo = append(prInfo, cms.PullRequestInformation{
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
			repoStat := cms.RepositoryInformation{
				Repository:      review.Repo,
				ReviewAdditions: int64(review.Additions),
				ReviewDeletions: int64(review.Deletions),
			}
			repoStats = append(repoStats, repoStat)
		}
		reviewInfo = append(reviewInfo, cms.ReviewInformation{
			URL:        review.PullRequestURL,
			State:      review.State,
			Number:     review.Number,
			Repository: review.Repo,
			Additions:  review.Additions,
			Deletions:  review.Deletions,
		})
	}

	userInfo.RepoDetails = repoStats
	userInfo.PRs = prInfo
	userInfo.Reviews = reviewInfo
	return userInfo
}
