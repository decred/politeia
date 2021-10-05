// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package api

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	"golang.org/x/oauth2"
)

// Client contains the http client that communicates with the Github
// servers, mutexes and api rate limiting rules.
type Client struct {
	sync.Mutex

	gh *http.Client

	rateLimit RateLimitRule
}

// NewClient creates a new instance of Client that contains a authorized
// client with the provided token argument.
func NewClient(token string) *Client {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{
			AccessToken: token,
		})
	gh := oauth2.NewClient(context.Background(), ts)

	return &Client{
		gh: gh,
	}
}

func (c *Client) sendGithubRequest(req *http.Request) ([]byte, error) {
	c.RateLimit()
	res, err := c.gh.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(res.Body)
	defer res.Body.Close()
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http returned %v", res.StatusCode)
	}
	return body, nil
}
