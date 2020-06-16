package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

const (
	apiReleasesURL = `https://api.github.com/repos/%s/%s/releases`
)

func (a *Client) FetchReleases(org, repo string) ([]*ApiRelease, error) {
	url := fmt.Sprintf(apiReleasesURL, org, repo)
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
		return nil, err
	}

	var releases []*ApiRelease
	err = json.Unmarshal(body, &releases)
	if err != nil {
		return nil, err
	}

	return releases, nil
}
