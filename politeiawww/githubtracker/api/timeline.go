package api

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

const (
	apiTimelineURL = `https://api.github.com/repos/%s/%s/issues/%d/timeline`
)

func (a *Client) Timeline(org, repo string, issueNum int) ([]byte, error) {
	url := fmt.Sprintf(apiTimelineURL, org, repo, issueNum)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", "application/vnd.github.mockingbird-preview")
	a.RateLimit()
	b, err := a.gh.Do(req)
	if err != nil {
		return nil, err
	}
	defer b.Body.Close()

	if b.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http returned %v", b.StatusCode)
	}

	return ioutil.ReadAll(b.Body)
}
