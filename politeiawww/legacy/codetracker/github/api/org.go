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
	apiOrgReposURL = `https://api.github.com/users/%s/repos?per_page=250`
)

// FetchOrgRepos requests all repos that are underneath the given organization.
func (a *Client) FetchOrgRepos(org string) ([]*Repository, error) {
	url := fmt.Sprintf(apiOrgReposURL, org)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	body, err := a.sendGithubRequest(req)
	if err != nil {
		return nil, err
	}

	var repos []*Repository
	err = json.Unmarshal(body, &repos)
	if err != nil {
		return nil, err
	}

	return repos, nil
}
