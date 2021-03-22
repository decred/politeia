// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package dcrdata

import (
	"fmt"
	"net/http"
	"sync"

	"github.com/decred/dcrd/chaincfg/v3"
	exptypes "github.com/decred/dcrdata/explorer/types/v2"
	pstypes "github.com/decred/dcrdata/pubsub/types/v3"
	backend "github.com/decred/politeia/politeiad/backendv2"
	"github.com/decred/politeia/politeiad/backendv2/tstorebe/plugins"
	"github.com/decred/politeia/politeiad/plugins/dcrdata"
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/wsdcrdata"
)

const (
	// Dcrdata http routes
	routeBestBlock    = "/api/block/best"
	routeBlockDetails = "/api/block/{height}"
	routeTicketPool   = "/api/stake/pool/b/{hash}/full"
	routeTxsTrimmed   = "/api/txs/trimmed"

	// Request headers
	headerContentType = "Content-Type"

	// Header values
	contentTypeJSON = "application/json; charset=utf-8"
)

var (
	_ plugins.PluginClient = (*dcrdataPlugin)(nil)
)

// dcrdataPlugin is the tstore backend implementation of the dcrdata plugin.
// The dcrdata plugin provides and API for interacting with the dcrdata http
// and websocket APIs.
//
// dcrdataPlugin satisfies the plugins PluginClient interface.
type dcrdataPlugin struct {
	sync.Mutex
	activeNetParams *chaincfg.Params
	client          *http.Client
	ws              *wsdcrdata.Client

	// Plugin settings
	hostHTTP string // dcrdata HTTP host
	hostWS   string // dcrdata websocket host

	// bestBlock is the cached best block height. This field is kept up
	// to date by the websocket connection. If the websocket connection
	// drops, the best block is marked as stale and is not marked as
	// current again until the connection has been re-established and
	// a new best block message is received.
	bestBlock      uint32
	bestBlockStale bool
}

// bestBlockGet returns the cached best block.
func (p *dcrdataPlugin) bestBlockGet() uint32 {
	p.Lock()
	defer p.Unlock()

	return p.bestBlock
}

// bestBlockSet sets the cached best block to a new value.
func (p *dcrdataPlugin) bestBlockSet(bb uint32) {
	p.Lock()
	defer p.Unlock()

	p.bestBlock = bb
	p.bestBlockStale = false
}

// bestBlockSetStale marks the cached best block as stale.
func (p *dcrdataPlugin) bestBlockSetStale() {
	p.Lock()
	defer p.Unlock()

	p.bestBlockStale = true
}

// bestBlockIsStale returns whether the cached best block has been marked as
// being stale.
func (p *dcrdataPlugin) bestBlockIsStale() bool {
	p.Lock()
	defer p.Unlock()

	return p.bestBlockStale
}

func (p *dcrdataPlugin) websocketMonitor() {
	defer func() {
		log.Infof("Dcrdata websocket closed")
	}()

	// Setup messages channel
	receiver := p.ws.Receive()

	for {
		// Monitor for a new message
		msg, ok := <-receiver
		if !ok {
			// Check if the websocket was shut down intentionally or was
			// dropped unexpectedly.
			if p.ws.Status() == wsdcrdata.StatusShutdown {
				return
			}
			log.Infof("Dcrdata websocket connection unexpectedly dropped")
			goto reconnect
		}

		// Handle new message
		switch m := msg.Message.(type) {
		case *exptypes.WebsocketBlock:
			log.Debugf("WebsocketBlock: %v", m.Block.Height)

			// Update cached best block
			p.bestBlockSet(uint32(m.Block.Height))

		case *pstypes.HangUp:
			log.Infof("Dcrdata websocket has hung up. Will reconnect.")
			goto reconnect

		case int:
			// Ping messages are of type int

		default:
			log.Errorf("ws message of type %v unhandled: %v",
				msg.EventId, m)
		}

		// Check for next message
		continue

	reconnect:
		// Mark cached best block as stale
		p.bestBlockSetStale()

		// Reconnect
		p.ws.Reconnect()

		// Setup a new messages channel using the new connection.
		receiver = p.ws.Receive()

		log.Infof("Dcrdata websocket successfully reconnected")
	}
}

func (p *dcrdataPlugin) websocketSetup() {
	// Setup websocket subscriptions
	var done bool
	for !done {
		// Best block
		err := p.ws.NewBlockSubscribe()
		if err != nil && err != wsdcrdata.ErrDuplicateSub {
			log.Errorf("dcrdataPlugin: NewBlockSubscribe: %v", err)
			goto reconnect
		}

		// All subscriptions setup
		done = true
		continue

	reconnect:
		p.ws.Reconnect()
	}

	// Monitor websocket connection
	go p.websocketMonitor()
}

// Setup performs any plugin setup that is required.
//
// This function satisfies the plugins PluginClient interface.
func (p *dcrdataPlugin) Setup() error {
	log.Tracef("dcrdata Setup")

	// Setup dcrdata websocket subscriptions and monitoring. This is
	// done in a go routine so setup will continue in the event that
	// a dcrdata websocket connection was not able to be made during
	// client initialization and reconnection attempts are required.
	go p.websocketSetup()

	return nil
}

// Cmd executes a plugin command.
//
// This function satisfies the plugins PluginClient interface.
func (p *dcrdataPlugin) Cmd(treeID int64, token []byte, cmd, payload string) (string, error) {
	log.Tracef("dcrdata Cmd: %v %x %v %v", treeID, token, cmd, payload)

	switch cmd {
	case dcrdata.CmdBestBlock:
		return p.cmdBestBlock(payload)
	case dcrdata.CmdBlockDetails:
		return p.cmdBlockDetails(payload)
	case dcrdata.CmdTicketPool:
		return p.cmdTicketPool(payload)
	case dcrdata.CmdTxsTrimmed:
		return p.cmdTxsTrimmed(payload)
	}

	return "", backend.ErrPluginCmdInvalid
}

// Hook executes a plugin hook.
//
// This function satisfies the plugins PluginClient interface.
func (p *dcrdataPlugin) Hook(treeID int64, token []byte, h plugins.HookT, payload string) error {
	log.Tracef("dcrdata Hook: %v %x %v", plugins.Hooks[h], token, treeID)

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the plugins PluginClient interface.
func (p *dcrdataPlugin) Fsck(treeIDs []int64) error {
	log.Tracef("dcrdata Fsck")

	return nil
}

// Settings returns the plugin's settings.
//
// This function satisfies the plugins PluginClient interface.
func (p *dcrdataPlugin) Settings() []backend.PluginSetting {
	log.Tracef("dcrdata Settings")

	return nil
}

func New(settings []backend.PluginSetting, activeNetParams *chaincfg.Params) (*dcrdataPlugin, error) {
	// Plugin setting
	var (
		hostHTTP string
		hostWS   string
	)

	// Set plugin settings to defaults. These will be overwritten if
	// the setting was specified by the user.
	switch activeNetParams.Name {
	case chaincfg.MainNetParams().Name:
		hostHTTP = dcrdata.SettingHostHTTPMainNet
		hostWS = dcrdata.SettingHostWSMainNet
	case chaincfg.TestNet3Params().Name:
		hostHTTP = dcrdata.SettingHostHTTPTestNet
		hostWS = dcrdata.SettingHostWSTestNet
	default:
		return nil, fmt.Errorf("unknown active net: %v", activeNetParams.Name)
	}

	// Override defaults with any passed in settings
	for _, v := range settings {
		switch v.Key {
		case dcrdata.SettingKeyHostHTTP:
			hostHTTP = v.Value
			log.Infof("Plugin setting updated: dcrdata %v %v",
				dcrdata.SettingKeyHostHTTP, hostHTTP)

		case dcrdata.SettingKeyHostWS:
			hostWS = v.Value
			log.Infof("Plugin setting updated: dcrdata %v %v",
				dcrdata.SettingKeyHostWS, hostWS)

		default:
			return nil, fmt.Errorf("invalid plugin setting '%v'", v.Key)
		}
	}

	// Setup http client
	log.Infof("Dcrdata HTTP host: %v", hostHTTP)
	client, err := util.NewHTTPClient(false, "")
	if err != nil {
		return nil, err
	}

	// Setup websocket client
	ws, err := wsdcrdata.New(hostWS)
	if err != nil {
		// Continue even if a websocket connection was not able to be
		// made. Reconnection attempts will be made in the plugin setup.
		log.Errorf("wsdcrdata New: %v", err)
	}

	return &dcrdataPlugin{
		activeNetParams: activeNetParams,
		client:          client,
		ws:              ws,
		hostHTTP:        hostHTTP,
		hostWS:          hostWS,
	}, nil
}
