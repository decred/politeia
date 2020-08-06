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
	apiCommitURL             = `https://api.github.com/repos/%s/%s/commits/%s`
	apiPullRequestCommitsURL = `https://api.github.com/repos/%s/%s/pulls/%d/commits?per_page=250&page=%d&sort=updated&direction=desc`
)

// FetchCommit requests a given commit based on organization, repo and hash
func (a *Client) FetchCommit(org, repo string, sha string) (*PullRequestCommit, error) {
	url := fmt.Sprintf(apiCommitURL, org, repo, sha)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	body, err := a.sendGithubRequest(req)
	if err != nil {
		return nil, err
	}

	var commit PullRequestCommit
	err = json.Unmarshal(body, &commit)
	if err != nil {
		return nil, err
	}

	return &commit, nil
}

// FetchPullRequestCommits requests all of the commits under a given pull
// request based on the organization, repo, and pull request number.
func (a *Client) FetchPullRequestCommits(org, repo string, prNum int) ([]PullRequestCommit, error) {
	var totalPullRequestCommits []PullRequestCommit
	page := 1
	for {
		url := fmt.Sprintf(apiPullRequestCommitsURL, org, repo, prNum, page)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return totalPullRequestCommits, err
		}
		body, err := a.sendGithubRequest(req)
		if err != nil {
			return totalPullRequestCommits, err
		}

		var pullRequestCommits []PullRequestCommit
		err = json.Unmarshal(body, &pullRequestCommits)
		if err != nil {
			return totalPullRequestCommits, err
		}

		// no more left
		if len(pullRequestCommits) == 0 {
			break
		}

		totalPullRequestCommits = append(totalPullRequestCommits, pullRequestCommits...)
		page++
	}
	return totalPullRequestCommits, nil

}
