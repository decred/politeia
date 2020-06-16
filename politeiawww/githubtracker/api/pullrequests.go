package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

const (
	apiPullsRequestURL       = `https://api.github.com/repos/%s/%s/pulls?per_page=250&page=%d&state=all&sort=updated&direction=desc`
	apiPullRequestURL        = `https://api.github.com/repos/%s/%s/pulls/%d`
	apiPullRequestCommitsURL = `https://api.github.com/repos/%s/%s/pulls/%d/commits?per_page=250&page=%d&sort=updated&direction=desc`
)

func (a *Client) FetchPullRequest(org, repo string, prNum int) (*ApiPullRequest, error) {
	url := fmt.Sprintf(apiPullRequestURL, org, repo, prNum)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	a.RateLimit()
	res, err := a.gh.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http returned %v", res.StatusCode)
	}

	body, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return nil, err
	}

	var pullRequest ApiPullRequest
	err = json.Unmarshal(body, &pullRequest)
	if err != nil {
		return nil, err
	}

	return &pullRequest, nil
}

// FetchPullsRequest
func (a *Client) FetchPullsRequest(org, repo string) ([]ApiPullsRequest, error) {
	var totalPullsRequests []ApiPullsRequest
	page := 1
	for {
		url := fmt.Sprintf(apiPullsRequestURL, org, repo, page)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return totalPullsRequests, err
		}
		a.RateLimit()
		res, err := a.gh.Do(req)
		if err != nil {
			return totalPullsRequests, err
		}

		body, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			return totalPullsRequests, err
		}

		var pullsRequests []ApiPullsRequest
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

func (a *Client) FetchPullRequestCommits(org, repo string, prNum int, monthYear time.Time) ([]ApiPullRequestCommit, error) {
	var totalPullRequestCommits []ApiPullRequestCommit
	page := 1
	for {
		url := fmt.Sprintf(apiPullRequestCommitsURL, org, repo, prNum, page)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return totalPullRequestCommits, err
		}
		a.RateLimit()
		res, err := a.gh.Do(req)
		if err != nil {
			return totalPullRequestCommits, err
		}

		body, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			return totalPullRequestCommits, err
		}

		var pullRequestCommits []ApiPullRequestCommit
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
