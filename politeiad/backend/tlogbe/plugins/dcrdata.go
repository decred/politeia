// Copyright (c) 2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package plugins

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	v4 "github.com/decred/dcrdata/api/types/v4"
	exptypes "github.com/decred/dcrdata/explorer/types/v2"
	pstypes "github.com/decred/dcrdata/pubsub/types/v3"
	"github.com/decred/politeia/plugins/dcrdata"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe"
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/wsdcrdata"
)

const (
	// Dcrdata routes
	routeBestBlock    = "/api/block/best"
	routeBlockDetails = "/api/block/{height}"
	routeTicketPool   = "/api/stake/pool/b/{hash}/full"
	routeTxsTrimmed   = "/api/txs/trimmed"
)

var (
	_ tlogbe.Plugin = (*dcrdataPlugin)(nil)
)

// dcrdataplugin satisfies the Plugin interface.
type dcrdataPlugin struct {
	sync.Mutex
	host   string
	client *http.Client      // HTTP client
	ws     *wsdcrdata.Client // Websocket client

	// bestBlock is the cached best block height. This field is kept up
	// to date by the websocket connection. If the websocket connection
	// drops, the best block is marked as stale and is not marked as
	// current again until the connection has been re-established and
	// a new best block message is received.
	bestBlock      uint32
	bestBlockStale bool
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
	p.bestBlockStale = false
}

func (p *dcrdataPlugin) bestBlockSetStale() {
	p.Lock()
	defer p.Unlock()

	p.bestBlockStale = true
}

func (p *dcrdataPlugin) bestBlockIsStale() bool {
	p.Lock()
	defer p.Unlock()

	return p.bestBlockStale
}

func (p *dcrdataPlugin) makeReq(method string, route string, v interface{}) ([]byte, error) {
	var (
		url     = p.host + route
		reqBody []byte
		err     error
	)

	log.Tracef("%v %v", method, url)

	// Setup request body
	if v != nil {
		reqBody, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	}

	// Send request
	req, err := http.NewRequest(method, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	r, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()

	// Handle response
	if r.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("%v %v %v %v",
				r.StatusCode, method, url, err)
		}
		return nil, fmt.Errorf("%v %v %v %s",
			r.StatusCode, method, url, body)
	}

	resBody := util.ConvertBodyToByteArray(r.Body, false)
	return resBody, nil
}

// bestBlockHTTP fetches and returns the best block from the dcrdata http API.
func (p *dcrdataPlugin) bestBlockHTTP() (*v4.BlockDataBasic, error) {
	resBody, err := p.makeReq(http.MethodGet, routeBestBlock, nil)
	if err != nil {
		return nil, err
	}

	var bdb v4.BlockDataBasic
	err = json.Unmarshal(resBody, &bdb)
	if err != nil {
		return nil, err
	}

	return &bdb, nil
}

// blockDetailsHTTP fetches and returns the block details from the dcrdata API
// for the provided block height.
func (p *dcrdataPlugin) blockDetailsHTTP(height uint32) (*v4.BlockDataBasic, error) {
	h := strconv.FormatUint(uint64(height), 10)

	route := strings.Replace(routeBlockDetails, "{height}", h, 1)
	resBody, err := p.makeReq(http.MethodGet, route, nil)
	if err != nil {
		return nil, err
	}

	var bdb v4.BlockDataBasic
	err = json.Unmarshal(resBody, &bdb)
	if err != nil {
		return nil, err
	}

	return &bdb, nil
}

// ticketPoolHTTP fetches and returns the list of tickets in the ticket pool
// from the dcrdata API at the provided block hash.
func (p *dcrdataPlugin) ticketPoolHTTP(blockHash string) ([]string, error) {
	route := strings.Replace(routeTicketPool, "{hash}", blockHash, 1)
	route += "?sort=true"
	resBody, err := p.makeReq(http.MethodGet, route, nil)
	if err != nil {
		return nil, err
	}

	var tickets []string
	err = json.Unmarshal(resBody, &tickets)
	if err != nil {
		return nil, err
	}

	return tickets, nil
}

// txsTrimmedHTTP fetches and returns the TrimmedTx from the dcrdata API for
// the provided tx IDs.
func (p *dcrdataPlugin) txsTrimmedHTTP(txIDs []string) ([]v4.TrimmedTx, error) {
	t := v4.Txns{
		Transactions: txIDs,
	}
	resBody, err := p.makeReq(http.MethodPost, routeTxsTrimmed, t)
	if err != nil {
		return nil, err
	}

	var txs []v4.TrimmedTx
	err = json.Unmarshal(resBody, &txs)
	if err != nil {
		return nil, err
	}

	return txs, nil
}

// cmdBestBlock returns the best block. If the dcrdata websocket has been
// disconnected the best block will be fetched from the dcrdata API. If dcrdata
// cannot be reached then the most recent cached best block will be returned
// along with a status of StatusDisconnected. It is the callers responsibility
// to determine if the stale best block should be used.
func (p *dcrdataPlugin) cmdBestBlock(payload string) (string, error) {
	log.Tracef("dcrdata cmdBestBlock")

	// Payload is empty. Nothing to decode.

	// Get the cached best block
	bb := p.bestBlockGet()
	var (
		fetch  bool
		stale  uint32
		status = dcrdata.StatusConnected
	)
	switch {
	case bb == 0:
		// No cached best block means that the best block has not been
		// populated by the websocket yet. Fetch is manually.
		fetch = true
	case p.bestBlockIsStale():
		// The cached best block has been populated by the websocket, but
		// the websocket is currently disconnected and the cached value
		// is stale. Try to fetch the best block manually and only use
		// the stale value if manually fetching it fails.
		fetch = true
		stale = bb
	}

	// Fetch the best block manually if required
	if fetch {
		block, err := p.bestBlockHTTP()
		switch {
		case err == nil:
			// We got the best block. Use it.
			bb = block.Height
		case stale != 0:
			// Unable to fetch the best block manually. Use the stale
			// value and mark the connection status as disconnected.
			bb = stale
			status = dcrdata.StatusDisconnected
		default:
			// Unable to fetch the best block manually and there is no
			// stale cached value to return.
			return "", fmt.Errorf("bestBlockHTTP: %v", err)
		}
	}

	// Prepare reply
	bbr := dcrdata.BestBlockReply{
		Status: status,
		Height: bb,
	}
	reply, err := dcrdata.EncodeBestBlockReply(bbr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *dcrdataPlugin) cmdBlockDetails(payload string) (string, error) {
	log.Tracef("dcrdata cmdBlockDetails: %v", payload)

	// Decode payload
	bd, err := dcrdata.DecodeBlockDetails([]byte(payload))
	if err != nil {
		return "", err
	}

	// Fetch block details
	bdb, err := p.blockDetailsHTTP(bd.Height)
	if err != nil {
		return "", fmt.Errorf("blockDetailsHTTP: %v", err)
	}

	// Prepare reply
	bdr := dcrdata.BlockDetailsReply{
		Block: *bdb,
	}
	reply, err := dcrdata.EncodeBlockDetailsReply(bdr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *dcrdataPlugin) cmdTicketPool(payload string) (string, error) {
	log.Tracef("dcrdata cmdTicketPool: %v", payload)

	// Decode payload
	tp, err := dcrdata.DecodeTicketPool([]byte(payload))
	if err != nil {
		return "", err
	}

	// Get the ticket pool
	tickets, err := p.ticketPoolHTTP(tp.BlockHash)
	if err != nil {
		return "", fmt.Errorf("ticketPoolHTTP: %v", err)
	}

	// Prepare reply
	tpr := dcrdata.TicketPoolReply{
		Tickets: tickets,
	}
	reply, err := dcrdata.EncodeTicketPoolReply(tpr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *dcrdataPlugin) cmdTxsTrimmed(payload string) (string, error) {
	log.Tracef("cmdTxsTrimmed: %v", payload)

	// Decode payload
	tt, err := dcrdata.DecodeTxsTrimmed([]byte(payload))
	if err != nil {
		return "", err
	}

	// Get trimmed txs
	txs, err := p.txsTrimmedHTTP(tt.TxIDs)
	if err != nil {
		return "", fmt.Errorf("txsTrimmedHTTP: %v", err)
	}

	// Prepare reply
	ttr := dcrdata.TxsTrimmedReply{
		Txs: txs,
	}
	reply, err := dcrdata.EncodeTxsTrimmedReply(ttr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

// Cmd executes a plugin command.
//
// This function satisfies the Plugin interface.
func (p *dcrdataPlugin) Cmd(cmd, payload string) (string, error) {
	log.Tracef("dcrdata Cmd: %v", cmd)

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
// This function satisfies the Plugin interface.
func (p *dcrdataPlugin) Hook(h tlogbe.HookT, payload string) error {
	log.Tracef("dcrdata Hook: %v %v", tlogbe.Hooks[h], payload)

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the Plugin interface.
func (p *dcrdataPlugin) Fsck() error {
	log.Tracef("dcrdata Fsck")

	return nil
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
			log.Debugf("dcrdata WebsocketBlock: %v", m.Block.Height)

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

		log.Infof("Successfully reconnected dcrdata websocket")
	}
}

func (p *dcrdataPlugin) websocketSetup() {
	// Setup websocket subscriptions
	var done bool
	for !done {
		// Best block
		err := p.ws.NewBlockSubscribe()
		if err != nil && err != wsdcrdata.ErrDuplicateSub {
			log.Errorf("NewBlockSubscribe: %v", err)
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

// Setup performs any plugin setup work that needs to be done.
//
// This function satisfies the Plugin interface.
func (p *dcrdataPlugin) Setup() error {
	log.Tracef("dcrdata Setup")

	// Setup dcrdata websocket subscriptions and monitoring. This is
	// done in a go routine so setup will continue in the event that
	// a dcrdata websocket connection was not able to be made during
	// client initialization and reconnection attempts are required.
	go p.websocketSetup()

	return nil
}

func DcrdataPluginNew(settings []backend.PluginSetting) *dcrdataPlugin {
	// TODO these should be passed in as plugin settings
	var dcrdataHost string

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
		// Continue even if a websocket connection was not able to be
		// made. Reconnection attempts will be made in the plugin setup.
		log.Errorf("wsdcrdata New: %v", err)
	}

	return &dcrdataPlugin{
		host:   dcrdataHost,
		client: client,
		ws:     ws,
	}
}
