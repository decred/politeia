// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

const (
	apiCommitURL = `https://api.github.com/repos/%s/%s/commits/%s`
)

func (a *Client) FetchCommit(org, repo string, sha string) (*ApiPullRequestCommit, error) {
	url := fmt.Sprintf(apiCommitURL, org, repo, sha)
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

	var commit ApiPullRequestCommit
	err = json.Unmarshal(body, &commit)
	if err != nil {
		return nil, err
	}

	return &commit, nil
}
