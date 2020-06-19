package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

const (
	apiPullRequestReviewsURL = `https://api.github.com/repos/%s/%s/pulls/%d/reviews?per_page=250&page=1`
)

func (a *Client) FetchPullRequestReviews(org, repo string, prNum int, lastUpdated time.Time) ([]ApiPullRequestReview, error) {
	var totalPullRequestReviews []ApiPullRequestReview
	url := fmt.Sprintf(apiPullRequestReviewsURL, org, repo, prNum)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	a.RateLimit()
	res, err := a.gh.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return totalPullRequestReviews, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http returned %v", res.StatusCode)
	}
	if len(body) == 0 {
		return totalPullRequestReviews, nil
	}

	var pullRequestReviews []ApiPullRequestReview
	err = json.Unmarshal(body, &pullRequestReviews)
	if err != nil {
		return totalPullRequestReviews, err
	}
	totalPullRequestReviews = append(totalPullRequestReviews, pullRequestReviews...)

	return totalPullRequestReviews, nil
}
