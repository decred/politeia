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

// github contains the client that communicates with the github api and an
// instance of the codedb that contains all of the pull request/review
// information that is fetched.
type github struct {
	tc     *api.Client
	codedb database.Database
}

// New creates a new github tracker that saves is able to communicate with
// the Github user/PR/issue API.
func New(apiToken, host, rootCert, cert, key string) (*github, error) {
	var err error
	g := &github{}
	g.tc = api.NewClient(apiToken)
	g.codedb, err = cockroachdb.New(host, rootCert, cert, key)
	if err == database.ErrNoVersionRecord || err == database.ErrWrongVersion {
		log.Errorf("New DB failed no version, wrong version: %v", err)
		return nil, err
	} else if err != nil {
		log.Errorf("New DB failed: %v", err)
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
func (g *github) Update(org string, repos []string, start, end int64) {
	for _, repo := range repos {
		log.Infof("%s", repo)
		log.Infof("Syncing %s/%s", org, repo)

		// Grab latest sync time
		prs, err := g.tc.FetchPullsRequest(org, repo)
		if err != nil {
			log.Errorf("error fetching repo pullrequest %s/%s %v", org, repo,
				err)
			continue
		}

		for _, pr := range prs {
			// check to see if last updated time was before the given start date
			if parseTime(pr.UpdatedAt).Before(time.Unix(start, 0)) {
				continue
			}
			if parseTime(pr.UpdatedAt).After(time.Unix(end, 0)) {
				continue
			}
			err := g.updatePullRequest(org, repo, pr, start)
			if err != nil {
				log.Errorf("updatePullRequest for %s/%s %v %v", org, repo,
					pr.Number, err)
			}
		}
	}
}

func (g *github) updatePullRequest(org, repoName string, pr api.PullsRequest, start int64) error {
	log.Infof("Updating %v/%v/%v ", org, repoName, pr.Number)
	apiPullRequest, err := g.fetchPullRequest(org, repoName, pr.Number)
	if err != nil {
		return err
	}
	dbPR, err := g.codedb.PullRequestByURL(apiPullRequest.URL)
	if err == database.ErrNoPullRequestFound {
		// Add a new entry since there is nothing there now.
		err = g.codedb.NewPullRequest(apiPullRequest)
		if err != nil {
			log.Errorf("error adding new pull request: %v", err)
			return err
		}
	} else {
		log.Errorf("error finding PR in db", err)
		return err
	}

	// Only add a new entry into the database if the updated time from the api,
	// is after the updated time in the db.  This should weed out re-adding
	// PRs that were previously merged.
	if time.Unix(apiPullRequest.UpdatedAt, 0).After(time.Unix(dbPR.UpdatedAt, 0)) {
		err = g.codedb.NewPullRequest(apiPullRequest)
		if err != nil {
			log.Errorf("error adding new pull request: %v", err)
			return err
		}
	}

	reviews, err := g.fetchPullRequestReviews(org, repoName, pr.Number,
		apiPullRequest.URL)
	if err != nil {
		return err
	}
	for _, review := range reviews {
		_, err := g.codedb.ReviewByID(review.ID)
		if err == database.ErrNoPullRequestReviewFound {
			// Add a new entry since there is nothing there now.
			err = g.codedb.NewPullRequestReview(&review)
			if err != nil {
				log.Errorf("error adding new pull request review: %v", err)
				continue
			}
		} else {
			log.Errorf("error finding Pull Request Review in db", err)
			return err
		}
	}
	return nil
}

func (g *github) fetchPullRequest(org, repoName string, prNum int) (*database.PullRequest, error) {
	apiPR, err := g.tc.FetchPullRequest(org, repoName, prNum)
	if err != nil {
		return nil, err
	}
	dbPullRequest, err := convertAPIPullRequestToDbPullRequest(apiPR, repoName,
		org)
	if err != nil {
		log.Errorf("error converting api PR to database: %v", err)
		return nil, err
	}
	return dbPullRequest, nil
}

func (g *github) fetchPullRequestReviews(org, repoName string, prNum int, url string) ([]database.PullRequestReview, error) {
	prReviews, err := g.tc.FetchPullRequestReviews(org, repoName,
		prNum)
	if err != nil {
		return nil, err
	}

	reviews := convertAPIReviewsToDbReviews(prReviews, repoName, prNum, url)
	return reviews, nil
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
	userInfo := convertCodeStatsToUserInformation(dbUserPRs, dbReviews)
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
