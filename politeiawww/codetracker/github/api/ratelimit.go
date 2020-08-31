// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package api

import (
	"encoding/json"
	"io/ioutil"
	"time"
)

const (
	rateLimitURL = "https://api.github.com/rate_limit"
)

// RateLimit determines if the current rate limit for the client is about
// to be tripped.  If so, it will go to sleep for a given perioud of time.
func (a *Client) RateLimit() (RateLimitRule, error) {
	defer a.rateLimitMtx.Unlock()
	a.rateLimitMtx.Lock()

	for {
		if a.rateLimit.Remaining == 0 {
			b, err := a.gh.Get(rateLimitURL)
			if err != nil {
				return RateLimitRule{}, err
			}
			bo, err := ioutil.ReadAll(b.Body)
			b.Body.Close()
			if err != nil {
				return RateLimitRule{}, err
			}
			var apiRateLimit RateLimit
			err = json.Unmarshal(bo, &apiRateLimit)
			if err != nil {
				return RateLimitRule{}, err
			}
			core := apiRateLimit.Resources.Core
			if core.Remaining == 0 {
				exp := time.Unix(core.Reset, 0)
				dur := time.Until(exp)
				log.Debugf("RATELIMIT REACHED - SLEEPING %v", dur)
				time.Sleep(dur)
				continue
			}
			log.Debugf("NEW RATELIMIT LOADED - %d remaining, exp %v",
				core.Remaining, time.Unix(core.Reset, 0))
			a.rateLimit = core
		}
		a.rateLimit.Remaining--
		break
	}

	return a.rateLimit, nil
}
