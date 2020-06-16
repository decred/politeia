package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

const (
	apiOrgReposURL = `https://api.github.com/users/%s/repos?per_page=250`
)

func (a *Client) FetchOrgRepos(org string) ([]*ApiRepository, error) {
	a.RateLimit()
	url := fmt.Sprintf(apiOrgReposURL, org)
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

	var repos []*ApiRepository
	err = json.Unmarshal(body, &repos)
	if err != nil {
		return nil, err
	}

	return repos, nil
}
