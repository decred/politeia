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
	apiPullsRequestURL = `https://api.github.com/repos/%s/%s/pulls?per_page=250&page=%d&state=all&sort=updated&direction=desc`
	apiPullRequestURL  = `https://api.github.com/repos/%s/%s/pulls/%d`
)

// FetchPullRequest requests information about a given pull request based on
// organization, repo and pull request number.
func (a *Client) FetchPullRequest(org, repo string, prNum int) (*PullRequest, error) {
	url := fmt.Sprintf(apiPullRequestURL, org, repo, prNum)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	body, err := a.sendGithubRequest(req)
	if err != nil {
		return nil, err
	}

	var pullRequest PullRequest
	err = json.Unmarshal(body, &pullRequest)
	if err != nil {
		return nil, err
	}

	return &pullRequest, nil
}

// FetchPullsRequest requests all of the pull requests from a given repo
// under an organization.
func (a *Client) FetchPullsRequest(org, repo string) ([]PullsRequest, error) {
	var totalPullsRequests []PullsRequest
	page := 1
	for {
		url := fmt.Sprintf(apiPullsRequestURL, org, repo, page)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return totalPullsRequests, err
		}
		body, err := a.sendGithubRequest(req)
		if err != nil {
			return totalPullsRequests, err
		}

		var pullsRequests []PullsRequest
		err = json.Unmarshal(body, &pullsRequests)
		if err != nil {
			return totalPullsRequests, err
		}

		// no more left
		if len(pullsRequests) == 0 {
			break
		}

		totalPullsRequests = append(totalPullsRequests, pullsRequests...)
		page++
	}
	return totalPullsRequests, nil
}
