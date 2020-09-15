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

	"github.com/decred/politeia/decredplugin"
	pd "github.com/decred/politeia/politeiad/api/v1"
	"github.com/decred/politeia/util"
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

// getBestBlock fetches and returns the best block from politeiad using the
// decred plugin bestblock command.
func (p *politeiawww) getBestBlock() (uint64, error) {
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
