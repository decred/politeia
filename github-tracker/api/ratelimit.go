package api

import (
	"encoding/json"
	"io/ioutil"
	"time"
)

func (a *Client) RateLimit() (ApiRateLimitRule, error) {
	defer a.rateLimitMtx.Unlock()
	a.rateLimitMtx.Lock()

	for {
		if a.rateLimit.Remaining == 0 {
			b, err := a.gh.Get("https://api.github.com/rate_limit")
			if err != nil {
				return ApiRateLimitRule{}, err
			}
			bo, err := ioutil.ReadAll(b.Body)
			b.Body.Close()
			if err != nil {
				return ApiRateLimitRule{}, err
			}
			var apiRateLimit ApiRateLimit
			err = json.Unmarshal(bo, &apiRateLimit)
			if err != nil {
				return ApiRateLimitRule{}, err
			}
			core := apiRateLimit.Resources.Core
			if core.Remaining == 0 {
				exp := time.Unix(core.Reset, 0)
				dur := time.Until(exp)
				log.Debugf("RATELIMIT REACHED - SLEEPING %v\n", dur)
				time.Sleep(dur)
				continue
			}
			log.Debugf("NEW RATELIMIT LOADED - %d remaining, exp %v", core.Remaining, time.Unix(core.Reset, 0))
			a.rateLimit = core
		}
		a.rateLimit.Remaining--
		break
	}

	return a.rateLimit, nil
}
