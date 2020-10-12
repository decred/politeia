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

// FetchPullRequestCommits requests all of the commit hashes under a given pull
// request based on the organization, repo, and pull request number.
func (a *Client) FetchPullRequestCommitSHAs(org, repo string, prNum int) ([]string, error) {
	totalPullRequestSHAs := make([]string, 0, 1048)
	page := 1
	for {
		fmt.Println("requesting pr commtis", repo, page)
		url := fmt.Sprintf(apiPullRequestCommitsURL, org, repo, prNum, page)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		body, err := a.sendGithubRequest(req)
		if err != nil {
			return nil, err
		}

		var pullRequestCommits []PullRequestCommit
		err = json.Unmarshal(body, &pullRequestCommits)
		if err != nil {
			return nil, err
		}

		// no more left
		if len(pullRequestCommits) == 0 {
			break
		}
		prSHAs := make([]string, 0, len(pullRequestCommits))
		for _, commit := range pullRequestCommits {
			prSHAs = append(prSHAs, commit.SHA)
		}
		totalPullRequestSHAs = append(totalPullRequestSHAs, prSHAs...)
		page++
	}
	return totalPullRequestSHAs, nil
}

// FetchPullRequestCommits returns a list of parsed commits based on org,
// repo and a list of hashes provided in the arguments.
func (a *Client) FetchPullRequestCommits(org, repo string, hashes []string) ([]*PullRequestCommit, error) {
	var totalCommits []*PullRequestCommit
	for _, sha := range hashes {
		commit, err := a.FetchCommit(org, repo, sha)
		if err != nil {
			log.Errorf("unable to fetch commit %v %v %v", org, repo, sha)
			continue
		}
		totalCommits = append(totalCommits, commit)
	}
	return totalCommits, nil
}
