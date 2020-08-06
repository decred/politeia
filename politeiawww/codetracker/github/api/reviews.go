// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	apiPullRequestReviewsURL = `https://api.github.com/repos/%s/%s/pulls/%d/reviews?per_page=250&page=1`
)

// FetchPullRequestReviews requests all of the reviews from a given pull request
// based on organization, repository, pull request number and time.
func (a *Client) FetchPullRequestReviews(org, repo string, prNum int) ([]PullRequestReview, error) {
	var totalPullRequestReviews []PullRequestReview
	url := fmt.Sprintf(apiPullRequestReviewsURL, org, repo, prNum)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	body, err := a.sendGithubRequest(req)
	if err != nil {
		return totalPullRequestReviews, err
	}
	if len(body) == 0 {
		return totalPullRequestReviews, nil
	}

	var pullRequestReviews []PullRequestReview
	err = json.Unmarshal(body, &pullRequestReviews)
	if err != nil {
		return totalPullRequestReviews, err
	}
	totalPullRequestReviews = append(totalPullRequestReviews, pullRequestReviews...)

	return totalPullRequestReviews, nil
}
