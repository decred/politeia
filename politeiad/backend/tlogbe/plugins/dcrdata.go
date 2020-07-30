// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package plugins

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	v4 "github.com/decred/dcrdata/api/types/v4"
	"github.com/decred/politeia/plugins/dcrdata"
)

const (
	// Dcrdata routes
	routeBestBlock = "/api/block/best"
)

var (
	_ Plugin = (*dcrdataPlugin)(nil)
)

// dcrdataplugin satisfies the Plugin interface.
type dcrdataPlugin struct {
	sync.Mutex
	host      string
	client    *http.Client
	bestBlock uint64
}

func (p *dcrdataPlugin) bestBlockGet() uint64 {
	p.Lock()
	defer p.Unlock()

	return p.bestBlock
}

// TODO move this to util
// bestBlockHTTP fetches the best block from the dcrdata API.
func (p *dcrdataPlugin) bestBlockHTTP() (*v4.BlockDataBasic, error) {
	url := p.host + routeBestBlock

	log.Tracef("dcrdata bestBlock: %v", url)

	r, err := p.client.Get(url)
	log.Debugf("http connecting to %v", url)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	if r.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("dcrdata error: %v %v %v",
				r.StatusCode, url, err)
		}
		return nil, fmt.Errorf("dcrdata error: %v %v %s",
			r.StatusCode, url, body)
	}

	var bdb v4.BlockDataBasic
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&bdb); err != nil {
		return nil, err
	}

	return &bdb, nil
}

// Cmd executes a plugin command.
//
// This function satisfies the Plugin interface.
func (p *dcrdataPlugin) Cmd(cmd, payload string) (string, error) {
	log.Tracef("dcrdata Cmd: %v", cmd)

	switch cmd {
	case dcrdata.CmdBestBlock:
		return p.cmdBestBlock(payload)
	}

	return "", ErrInvalidPluginCmd
}

// Hook executes a plugin hook.
//
// This function satisfies the Plugin interface.
func (p *dcrdataPlugin) Hook(h HookT, payload string) error {
	log.Tracef("dcrdata Hook: %v %v", h, payload)

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the Plugin interface.
func (p *dcrdataPlugin) Fsck() error {
	log.Tracef("dcrdata Fsck")

	return nil
}

// Setup performs any plugin setup work that needs to be done.
//
// This function satisfies the Plugin interface.
func (p *dcrdataPlugin) Setup() error {
	log.Tracef("dcrdata Setup")

	return nil
}

func DcrdataPluginNew(dcrdataHost string) *dcrdataPlugin {
	// Setup http client
	client := &http.Client{
		Timeout: 1 * time.Minute,
		Transport: &http.Transport{
			IdleConnTimeout:       1 * time.Minute,
			ResponseHeaderTimeout: 1 * time.Minute,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
	}

	return &dcrdataPlugin{
		host:   dcrdataHost,
		client: client,
	}
}
