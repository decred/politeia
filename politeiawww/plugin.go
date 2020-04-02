// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/thi4go/politeia/decredplugin"
	pd "github.com/thi4go/politeia/politeiad/api/v1"
	"github.com/thi4go/politeia/util"
)

// PluginSetting is a structure that holds key/value pairs of a plugin setting.
type PluginSetting struct {
	Key   string // Name of setting
	Value string // Value of setting
}

// Plugin describes a plugin and its settings.
type Plugin struct {
	ID       string          // Identifier
	Version  string          // Version
	Settings []PluginSetting // Settings
}

// getBestBlockDecredPlugin asks the decred plugin what the current best block
// is.
func (p *politeiawww) getBestBlockDecredPlugin() (uint64, error) {
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return 0, err
	}

	pc := pd.PluginCommand{
		Challenge: hex.EncodeToString(challenge),
		ID:        decredplugin.ID,
		Command:   decredplugin.CmdBestBlock,
		CommandID: decredplugin.CmdBestBlock,
		Payload:   "",
	}

	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginCommandRoute, pc)
	if err != nil {
		return 0, err
	}

	var reply pd.PluginCommandReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return 0, fmt.Errorf("Could not unmarshal "+
			"PluginCommandReply: %v", err)
	}

	// Verify the challenge.
	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return 0, err
	}

	bestBlock, err := strconv.ParseUint(reply.Payload, 10, 64)
	if err != nil {
		return 0, err
	}

	return bestBlock, nil
}

func (p *politeiawww) pluginInventory() ([]Plugin, error) {
	// Setup politeiad request
	challenge, err := util.Random(pd.ChallengeSize)
	if err != nil {
		return nil, err
	}

	pi := pd.PluginInventory{
		Challenge: hex.EncodeToString(challenge),
	}

	// Send politeiad request
	responseBody, err := p.makeRequest(http.MethodPost,
		pd.PluginInventoryRoute, pi)
	if err != nil {
		return nil, fmt.Errorf("makeRequest: %v", err)
	}

	// Handle response
	var reply pd.PluginInventoryReply
	err = json.Unmarshal(responseBody, &reply)
	if err != nil {
		return nil, err
	}

	err = util.VerifyChallenge(p.cfg.Identity, challenge, reply.Response)
	if err != nil {
		return nil, err
	}

	plugins := make([]Plugin, 0, len(reply.Plugins))
	for _, v := range reply.Plugins {
		plugins = append(plugins, convertPluginFromPD(v))
	}

	return plugins, nil
}

// getPluginInventory obtains the politeiad plugin inventory. If a politeiad
// connection cannot be made, the call will be retried every 5 seconds for up
// to 1000 tries.
func (p *politeiawww) getPluginInventory() ([]Plugin, error) {
	log.Tracef("getPluginInventory")

	// Attempt to fetch the plugin inventory from politeiad until
	// either it is successful or the maxRetries has been exceeded.
	var (
		maxRetries    = 1000
		sleepInterval = 5 * time.Second
		done          bool
		plugins       []Plugin
	)
	for retries := 0; !done; retries++ {
		if retries == maxRetries {
			return nil, fmt.Errorf("max retries exceeded")
		}

		p, err := p.pluginInventory()
		if err != nil {
			log.Infof("cannot get politeiad plugin inventory: %v", err)
			time.Sleep(sleepInterval)
			continue
		}

		plugins = p
		done = true
	}

	return plugins, nil
}
