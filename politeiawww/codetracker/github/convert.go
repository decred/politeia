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

func convertAPICommitsToDbCommits(apiCommits []api.PullRequestCommit, repoName string) []database.Commit {
	dbCommits := make([]database.Commit, 0, len(apiCommits))
	for _, commit := range apiCommits {
		dbCommit := convertAPICommitToDbCommit(commit)
		dbCommit.Repo = repoName
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

func convertCodeStatsToUserInformation(prs []*database.PullRequest, reviews []database.PullRequestReview, commits []database.Commit) *codetracker.UserInformationResult {
	repoStats := make([]codetracker.RepositoryInformation, 0, 1048) // PNOOMA
	userInfo := &codetracker.UserInformationResult{}
	prInfo := make([]codetracker.PullRequestInformation, 0, len(prs))
	reviewInfo := make([]codetracker.ReviewInformation, 0, len(reviews))
	commitInfo := make([]codetracker.CommitInformation, 0, len(commits))
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
			repoStat := codetracker.RepositoryInformation{
				PRs:            []string{pr.URL},
				Repository:     pr.Repo,
				MergeAdditions: int64(pr.Additions),
				MergeDeletions: int64(pr.Deletions),
			}
			repoStats = append(repoStats, repoStat)
		}
		prInfo = append(prInfo, codetracker.PullRequestInformation{
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

	for _, commit := range commits {
		repoFound := false
		for i, repoStat := range repoStats {
			if repoStat.Repository == commit.Repo {
				repoFound = true
				repoStat.CommitAdditions += int64(commit.Additions)
				repoStat.CommitDeletions += int64(commit.Deletions)
				repoStats[i] = repoStat
				break
			}
		}
		if !repoFound {
			repoStat := codetracker.RepositoryInformation{
				Repository:      commit.Repo,
				CommitAdditions: int64(commit.Additions),
				CommitDeletions: int64(commit.Deletions),
			}
			repoStats = append(repoStats, repoStat)
		}
		commitInfo = append(commitInfo, codetracker.CommitInformation{
			URL:       commit.URL,
			Additions: commit.Additions,
			Deletions: commit.Deletions,
			SHA:       commit.SHA,
			Author:    commit.Author,
			Committer: commit.Committer,
		})
	}
	userInfo.RepoDetails = repoStats
	userInfo.PRs = prInfo
	userInfo.Reviews = reviewInfo
	userInfo.Commits = commitInfo
	return userInfo
}
