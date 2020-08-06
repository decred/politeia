// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package github

import (
	"fmt"
	"time"

	"github.com/decred/politeia/politeiawww/codetracker"
	"github.com/decred/politeia/politeiawww/codetracker/github/api"
	"github.com/decred/politeia/politeiawww/codetracker/github/database"
	"github.com/decred/politeia/politeiawww/codetracker/github/database/cockroachdb"
)

// github implements the Tracker interface for github.
type github struct {
	tc     *api.Client
	codedb database.Database
}

// Setup creates a new github tracker that saves is able to communicate with the
// Github user/PR/issue API.
func New(apiToken, host, rootCert, cert, key string) (*github, error) {
	var err error
	g := &github{}
	g.tc = api.NewClient(apiToken)
	g.codedb, err = cockroachdb.New(host, rootCert, cert, key)
	if err == database.ErrNoVersionRecord || err == database.ErrWrongVersion {
		log.Errorf("New DB failed no version, wrong version: %v\n", err)
		return nil, err
	} else if err != nil {
		log.Errorf("New DB failed: %v\n", err)
		return nil, err
	}
	err = g.codedb.Setup()
	if err != nil {
		log.Errorf("codeDB setup failed: %v", err)
		return nil, err
	}
	return g, nil
}

// Update fetches all repos from the given organization and updates all
// users' information once the info is fully received.  If repoRequest is
// included then only that repo will be fetched and updated, typically
// used for speeding up testing.
func (g *github) Update(org string, repoRequest string) error {
	// Fetch the organization's repositories
	repos, err := g.tc.FetchOrgRepos(org)
	if err != nil {
		err = fmt.Errorf("FetchOrgRepos: %v", err)
		return err
	}

	for _, repo := range repos {
		// Allow for a repo argument for testing expediting.
		if repoRequest != "" && repo.Name != repoRequest {
			continue
		}

		log.Infof("%s", repo.Name)
		log.Infof("Syncing %s", repo.FullName)

		// Grab latest sync time
		prs, err := g.tc.FetchPullsRequest(org, repo.Name)
		if err != nil {
			return err
		}

		for _, pr := range prs {
			err := g.updatePullRequest(org, repo.Name, pr)
			if err != nil {
				log.Errorf("updatePullRequest fpr %v %v %v", repo.Name,
					pr.Number, err)
			}
		}
	}

	return nil
}

func (g *github) updatePullRequest(org, repoName string, pr api.PullsRequest) error {
	apiPR, err := g.tc.FetchPullRequest(org, repoName, pr.Number)
	if err != nil {
		return err
	}
	dbPullRequest, err := convertAPIPullRequestToDbPullRequest(apiPR, repoName,
		org)
	if err != nil {
		log.Errorf("error converting api PR to database: %v", err)
		return err
	}
	dbPR, err := g.codedb.PullRequestByURL(dbPullRequest.URL)
	if err == database.ErrNoPullRequestFound {
		log.Infof("New PR %d", pr.Number)
		commits, reviews, err := g.fetchPullRequestReviewsCommits(org,
			repoName, pr.Number)
		if err != nil {
			return err
		}
		dbPullRequest.Commits = commits
		dbPullRequest.Reviews = reviews
		err = g.codedb.NewPullRequest(dbPullRequest)
		if err != nil {
			log.Errorf("error adding new pull request: %v", err)
			return err
		}
		return nil
	} else if err != nil {
		log.Errorf("error locating pull request: %v", err)
		return err
	} else if dbPR != nil &&
		time.Unix(dbPR.UpdatedAt, 0).After(parseTime(pr.UpdatedAt)) {
		// Only update if dbPR is found and pr.Updated is more recent than what
		// is currently stored.
		log.Infof("Update PR %d", pr.Number)
		commits, reviews, err := g.fetchPullRequestReviewsCommits(org,
			repoName, pr.Number)
		if err != nil {
			return err
		}
		dbPullRequest.Commits = commits
		dbPullRequest.Reviews = reviews
		err = g.codedb.UpdatePullRequest(dbPullRequest)
		if err != nil {
			log.Errorf("error updating new pull request: %v", err)
			return err
		}
	}
	return nil
}

func (g *github) fetchPullRequestReviewsCommits(org, repoName string, prNum int) ([]database.Commit, []database.PullRequestReview, error) {
	prCommits, err := g.tc.FetchPullRequestCommits(org, repoName,
		prNum)
	if err != nil {
		return nil, nil, err
	}
	commits := convertAPICommitsToDbCommits(prCommits)
	prReviews, err := g.tc.FetchPullRequestReviews(org, repoName,
		prNum)
	if err != nil {
		return commits, nil, err
	}

	reviews := convertAPIReviewsToDbReviews(prReviews, repoName, prNum)
	return commits, reviews, nil
}
func yearMonth(t time.Time) string {
	return fmt.Sprintf("%d%02d", t.Year(), t.Month())
}

// UserInfo provides the converted information from pull requests and
// reviews for a given user of a given period of time.
func (g *github) UserInfo(org string, user string, year, month int) (*codetracker.UserInformationResult, error) {
	startDate := time.Date(year, time.Month(month), 0, 0, 0, 0, 0,
		time.UTC).Unix()
	endDate := time.Date(year, time.Month(month+1), 0, 0, 0, 0, 0,
		time.UTC).Unix()
	dbUserPRs, err := g.codedb.PullRequestsByUserDates(user, startDate, endDate)
	if err != nil {
		return nil, err
	}
	dbReviews, err := g.codedb.ReviewsByUserDates(user, startDate, endDate)
	if err != nil {
		return nil, err
	}
	userInfo := convertPRsandReviewsToUserInformation(dbUserPRs, dbReviews)
	userInfo.User = user
	userInfo.Organization = org
	return userInfo, nil
}

func parseTime(tstamp string) time.Time {
	t, err := time.Parse(time.RFC3339, tstamp)
	if err != nil {
		return time.Time{}
	}
	return t
}
