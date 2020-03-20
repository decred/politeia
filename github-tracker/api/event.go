package api

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

const (
	apiEventURL = `https://api.github.com/repos/%s/%s/issues/%d/events`
)

func (a *Client) FetchEvents(org, repo string, prNum int) ([]*ApiEvent, error) {
	url := fmt.Sprintf(apiEventURL, org, repo, prNum)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	res, err := a.gh.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return nil, err
	}

	var events []*ApiEvent
	err = json.Unmarshal(body, &events)
	if err != nil {
		return nil, err
	}

	return events, nil
}
