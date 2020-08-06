// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package api

import (
	"context"
	"net/http"
	"sync"

	"golang.org/x/oauth2"
)

type Client struct {
	gh *http.Client

	rateLimitMtx sync.Mutex
	rateLimit    ApiRateLimitRule
}

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
