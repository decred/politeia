package githubtracker

import (
	"encoding/binary"
	"fmt"
	"time"

	cms "github.com/decred/politeia/politeiawww/api/cms/v1"
	"github.com/decred/politeia/politeiawww/githubtracker/api"
	"github.com/decred/politeia/politeiawww/githubtracker/database"
)

// Tracker contains the client connection and github database that will
// store the information received from the client.
type Tracker struct {
	tc *api.Client
	DB database.Database
}

// NewTracker creates a new tracker that saves is able to communicate with the
// Github user/PR/issue API.
func NewTracker(token string) *Tracker {
	tc := api.NewClient(token)

	return &Tracker{
		tc: tc,
	}
}

// Update fetches all repos from the given organization and updates all
// users' information once the info is fully received.  If repoRequest is
// included then only that repo will be fetched and updated, typically
// used for speeding up testing.
func (t *Tracker) Update(org string, repoRequest string) error {
	// Fetch the organization's repositories
	repos, err := t.tc.FetchOrgRepos(org)
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
		prs, err := t.tc.FetchPullsRequest(org, repo.Name)
		if err != nil {
			return err
		}

		for _, pr := range prs {
			var prNum [8]byte
			binary.LittleEndian.PutUint64(prNum[:], uint64(pr.Number))

			apiPR, err := t.tc.FetchPullRequest(org, repo.Name, pr.Number)
			if err != nil {
				return err
			}
			dbPullRequest, err := convertAPIPullRequestToDbPullRequest(apiPR, *repo, org)
			if err != nil {
				log.Errorf("error converting api PR to database: %v", err)
				continue
			}
			dbPR, err := t.DB.PullRequestByURL(pr.URL)
			if err != nil {
				if err == database.ErrNoPullRequestFound {
					prCommits, err := t.tc.FetchPullRequestCommits(org, repo.Name, pr.Number, parseTime(pr.UpdatedAt))
					if err != nil {
						return err
					}

					commits := convertAPICommitsToDbCommits(prCommits)
					dbPullRequest.Commits = commits

					prReviews, err := t.tc.FetchPullRequestReviews(org, repo.Name, pr.Number, parseTime(pr.UpdatedAt))
					if err != nil {
						panic(err)
					}
					reviews := convertAPIReviewsToDbReviews(prReviews, repo.Name, pr.Number)
					dbPullRequest.Reviews = reviews

					err = t.DB.NewPullRequest(dbPullRequest)
					if err != nil {
						log.Errorf("error adding new pull request: %v", err)
						continue
					}
				} else {
					log.Errorf("error locating pull request: %v", err)
					continue
				}
			}
			// Only update if dbPR is found and Uqpdated is more recent than what is currently stored.
			if dbPR != nil && time.Unix(dbPR.UpdatedAt, 0).After(parseTime(pr.UpdatedAt)) {
				log.Infof("\tUpdate PR %d", pr.Number)
				prCommits, err := t.tc.FetchPullRequestCommits(org, repo.Name, pr.Number, parseTime(pr.UpdatedAt))
				if err != nil {
					return err
				}

				commits := convertAPICommitsToDbCommits(prCommits)
				dbPullRequest.Commits = commits

				prReviews, err := t.tc.FetchPullRequestReviews(org, repo.Name, pr.Number, parseTime(pr.UpdatedAt))
				if err != nil {
					panic(err)
				}

				reviews := convertAPIReviewsToDbReviews(prReviews, repo.Name, pr.Number)
				dbPullRequest.Reviews = reviews

				err = t.DB.UpdatePullRequest(dbPullRequest)
				if err != nil {
					log.Errorf("error updating new pull request: %v", err)
					continue
				}

			}
		}
	}

	return nil
}

func yearMonth(t time.Time) string {
	return fmt.Sprintf("%d%02d", t.Year(), t.Month())
}

// UserInformation provides the converted information from pull requests and
// reviews for a given user of a given period of time.
func (t *Tracker) UserInformation(org string, user string, year, month int) (*cms.UserInformationResult, error) {
	startDate := time.Date(year, time.Month(month), 0, 0, 0, 0, 0, time.UTC).Unix()
	endDate := time.Date(year, time.Month(month+1), 0, 0, 0, 0, 0, time.UTC).Unix()
	dbUserPRs, err := t.DB.PullRequestsByUserDates(user, startDate, endDate)
	if err != nil {
		return nil, err
	}
	dbReviews, err := t.DB.ReviewsByUserDates(user, startDate, endDate)
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
