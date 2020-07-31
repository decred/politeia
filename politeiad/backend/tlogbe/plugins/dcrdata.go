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
	exptypes "github.com/decred/dcrdata/explorer/types/v2"
	pstypes "github.com/decred/dcrdata/pubsub/types/v3"
	"github.com/decred/politeia/plugins/dcrdata"
	"github.com/decred/politeia/wsdcrdata"
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
	client    *http.Client      // HTTP client
	ws        *wsdcrdata.Client // Websocket client
	bestBlock uint32
}

func (p *dcrdataPlugin) bestBlockGet() uint32 {
	p.Lock()
	defer p.Unlock()

	return p.bestBlock
}

func (p *dcrdataPlugin) bestBlockSet(bb uint32) {
	p.Lock()
	defer p.Unlock()

	p.bestBlock = bb
}

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

func (p *dcrdataPlugin) monitorWebsocket() {
	defer func() {
		log.Infof("Dcrdata websocket closed")
	}()

	// Setup messages channel
	receiver, err := p.ws.Receive()
	if err == wsdcrdata.ErrShutdown {
		return
	} else if err != nil {
		log.Errorf("dcrdata Receive: %v", err)
	}

	for {
		// Monitor for a new message
		msg, ok := <-receiver
		if !ok {
			log.Infof("Dcrdata websocket channel closed. Will reconnect.")
			goto reconnect
		}

		// Handle new message
		switch m := msg.Message.(type) {
		case *exptypes.WebsocketBlock:
			log.Debugf("Dcrdata websocket new block %v", m.Block.Height)
			p.bestBlockSet(uint32(m.Block.Height))

		case *pstypes.HangUp:
			log.Infof("Dcrdata websocket has hung up. Will reconnect.")
			goto reconnect

		case int:
			// Ping messages are of type int

		default:
			log.Errorf("Dcrdata websocket unhandled msg %v", msg)
		}

		// Check for next message
		continue

	reconnect:
		// Connection was closed for some reason. Set the best block
		// to 0 to indicate that its stale then reconnect to dcrdata.
		p.bestBlockSet(0)
		err = p.ws.Reconnect()
		if err == wsdcrdata.ErrShutdown {
			return
		} else if err != nil {
			log.Errorf("dcrdata Reconnect: %v", err)
			continue
		}

		// Setup a new messages channel using the new connection.
		receiver, err = p.ws.Receive()
		if err == wsdcrdata.ErrShutdown {
			return
		} else if err != nil {
			log.Errorf("dcrdata Receive: %v", err)
			continue
		}

		log.Infof("Successfully reconnected dcrdata websocket")
	}
}

func (p *dcrdataPlugin) cmdBestBlock(payload string) (string, error) {
	log.Tracef("dcrdata cmdBestBlock")

	// Payload is empty. No need to decode it.

	bb := p.bestBlockGet()
	if bb == 0 {
		// No cached best block means the websocket connection is down.
		// Get the best block from the dcrdata API.
		block, err := p.bestBlockHTTP()
		if err != nil {
			return "", err
		}
	}

	return "", nil
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

	// Setup websocket subscriptions
	err := p.ws.NewBlockSubscribe()
	if err != nil {
		return err
	}

	// Monitor websocket connection in a new go routine
	go p.monitorWebsocket()

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

	// Setup websocket client
	ws, err := wsdcrdata.New(dcrdataHost)
	if err != nil {
		// TODO reconnect logic
	}

	return &dcrdataPlugin{
		host:   dcrdataHost,
		client: client,
		ws:     ws,
	}
}
