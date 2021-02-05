// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package dcrdata

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/decred/dcrd/chaincfg/v3"
	jsonrpc "github.com/decred/dcrd/rpc/jsonrpc/types/v2"
	v5 "github.com/decred/dcrdata/api/types/v5"
	exptypes "github.com/decred/dcrdata/explorer/types/v2"
	pstypes "github.com/decred/dcrdata/pubsub/types/v3"
	"github.com/decred/politeia/politeiad/backend"
	"github.com/decred/politeia/politeiad/backend/tlogbe/plugins"
	"github.com/decred/politeia/politeiad/plugins/dcrdata"
	"github.com/decred/politeia/util"
	"github.com/decred/politeia/wsdcrdata"
)

const (
	// Plugin settings
	pluginSettingHostHTTP = "hosthttp"
	pluginSettingHostWS   = "hostws"

	// Dcrdata routes
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

// dcrdataplugin satisfies the plugins.PluginClient interface.
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

func (p *dcrdataPlugin) makeReq(method string, route string, headers map[string]string, v interface{}) ([]byte, error) {
	var (
		url     = p.hostHTTP + route
		reqBody []byte
		err     error
	)

	log.Tracef("%v %v", method, url)

	// Setup request
	if v != nil {
		reqBody, err = json.Marshal(v)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Add(k, v)
	}

	// Send request
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

	return util.RespBody(r), nil
}

// bestBlockHTTP fetches and returns the best block from the dcrdata http API.
func (p *dcrdataPlugin) bestBlockHTTP() (*v5.BlockDataBasic, error) {
	resBody, err := p.makeReq(http.MethodGet, routeBestBlock, nil, nil)
	if err != nil {
		return nil, err
	}

	var bdb v5.BlockDataBasic
	err = json.Unmarshal(resBody, &bdb)
	if err != nil {
		return nil, err
	}

	return &bdb, nil
}

// blockDetailsHTTP fetches and returns the block details from the dcrdata API
// for the provided block height.
func (p *dcrdataPlugin) blockDetailsHTTP(height uint32) (*v5.BlockDataBasic, error) {
	h := strconv.FormatUint(uint64(height), 10)

	route := strings.Replace(routeBlockDetails, "{height}", h, 1)
	resBody, err := p.makeReq(http.MethodGet, route, nil, nil)
	if err != nil {
		return nil, err
	}

	var bdb v5.BlockDataBasic
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
	resBody, err := p.makeReq(http.MethodGet, route, nil, nil)
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
func (p *dcrdataPlugin) txsTrimmedHTTP(txIDs []string) ([]v5.TrimmedTx, error) {
	t := v5.Txns{
		Transactions: txIDs,
	}
	headers := map[string]string{
		headerContentType: contentTypeJSON,
	}
	resBody, err := p.makeReq(http.MethodPost, routeTxsTrimmed, headers, t)
	if err != nil {
		return nil, err
	}

	var txs []v5.TrimmedTx
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
	log.Tracef("cmdBestBlock: %v", payload)

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
	reply, err := json.Marshal(bbr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func convertTicketPoolInfoFromV5(t v5.TicketPoolInfo) dcrdata.TicketPoolInfo {
	return dcrdata.TicketPoolInfo{
		Height:  t.Height,
		Size:    t.Size,
		Value:   t.Value,
		ValAvg:  t.ValAvg,
		Winners: t.Winners,
	}
}

func convertBlockDataBasicFromV5(b v5.BlockDataBasic) dcrdata.BlockDataBasic {
	var poolInfo *dcrdata.TicketPoolInfo
	if b.PoolInfo != nil {
		p := convertTicketPoolInfoFromV5(*b.PoolInfo)
		poolInfo = &p
	}
	return dcrdata.BlockDataBasic{
		Height:     b.Height,
		Size:       b.Size,
		Hash:       b.Hash,
		Difficulty: b.Difficulty,
		StakeDiff:  b.StakeDiff,
		Time:       b.Time.UNIX(),
		NumTx:      b.NumTx,
		MiningFee:  b.MiningFee,
		TotalSent:  b.TotalSent,
		PoolInfo:   poolInfo,
	}
}

func (p *dcrdataPlugin) cmdBlockDetails(payload string) (string, error) {
	log.Tracef("cmdBlockDetails: %v", payload)

	// Decode payload
	var bd dcrdata.BlockDetails
	err := json.Unmarshal([]byte(payload), &bd)
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
		Block: convertBlockDataBasicFromV5(*bdb),
	}
	reply, err := json.Marshal(bdr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func (p *dcrdataPlugin) cmdTicketPool(payload string) (string, error) {
	log.Tracef("cmdTicketPool: %v", payload)

	// Decode payload
	var tp dcrdata.TicketPool
	err := json.Unmarshal([]byte(payload), &tp)
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
	reply, err := json.Marshal(tpr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
}

func convertScriptSigFromJSONRPC(s jsonrpc.ScriptSig) dcrdata.ScriptSig {
	return dcrdata.ScriptSig{
		Asm: s.Asm,
		Hex: s.Hex,
	}
}

func convertVinFromJSONRPC(v jsonrpc.Vin) dcrdata.Vin {
	var scriptSig *dcrdata.ScriptSig
	if v.ScriptSig != nil {
		s := convertScriptSigFromJSONRPC(*v.ScriptSig)
		scriptSig = &s
	}
	return dcrdata.Vin{
		Coinbase:    v.Coinbase,
		Stakebase:   v.Stakebase,
		Txid:        v.Txid,
		Vout:        v.Vout,
		Tree:        v.Tree,
		Sequence:    v.Sequence,
		AmountIn:    v.AmountIn,
		BlockHeight: v.BlockHeight,
		BlockIndex:  v.BlockIndex,
		ScriptSig:   scriptSig,
	}
}

func convertVinsFromV5(ins []jsonrpc.Vin) []dcrdata.Vin {
	i := make([]dcrdata.Vin, 0, len(ins))
	for _, v := range ins {
		i = append(i, convertVinFromJSONRPC(v))
	}
	return i
}

func convertScriptPubKeyFromV5(s v5.ScriptPubKey) dcrdata.ScriptPubKey {
	return dcrdata.ScriptPubKey{
		Asm:       s.Asm,
		Hex:       s.Hex,
		ReqSigs:   s.ReqSigs,
		Type:      s.Type,
		Addresses: s.Addresses,
		CommitAmt: s.CommitAmt,
	}
}

func convertTxInputIDFromV5(t v5.TxInputID) dcrdata.TxInputID {
	return dcrdata.TxInputID{
		Hash:  t.Hash,
		Index: t.Index,
	}
}

func convertVoutFromV5(v v5.Vout) dcrdata.Vout {
	var spend *dcrdata.TxInputID
	if v.Spend != nil {
		s := convertTxInputIDFromV5(*v.Spend)
		spend = &s
	}
	return dcrdata.Vout{
		Value:               v.Value,
		N:                   v.N,
		Version:             v.Version,
		ScriptPubKeyDecoded: convertScriptPubKeyFromV5(v.ScriptPubKeyDecoded),
		Spend:               spend,
	}
}

func convertVoutsFromV5(outs []v5.Vout) []dcrdata.Vout {
	o := make([]dcrdata.Vout, 0, len(outs))
	for _, v := range outs {
		o = append(o, convertVoutFromV5(v))
	}
	return o
}

func convertTrimmedTxFromV5(t v5.TrimmedTx) dcrdata.TrimmedTx {
	return dcrdata.TrimmedTx{
		TxID:     t.TxID,
		Version:  t.Version,
		Locktime: t.Locktime,
		Expiry:   t.Expiry,
		Vin:      convertVinsFromV5(t.Vin),
		Vout:     convertVoutsFromV5(t.Vout),
	}
}

func convertTrimmedTxsFromV5(txs []v5.TrimmedTx) []dcrdata.TrimmedTx {
	t := make([]dcrdata.TrimmedTx, 0, len(txs))
	for _, v := range txs {
		t = append(t, convertTrimmedTxFromV5(v))
	}
	return t
}

func (p *dcrdataPlugin) cmdTxsTrimmed(payload string) (string, error) {
	log.Tracef("cmdTxsTrimmed: %v", payload)

	// Decode payload
	var tt dcrdata.TxsTrimmed
	err := json.Unmarshal([]byte(payload), &tt)
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
		Txs: convertTrimmedTxsFromV5(txs),
	}
	reply, err := json.Marshal(ttr)
	if err != nil {
		return "", err
	}

	return string(reply), nil
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
// This function satisfies the plugins.PluginClient interface.
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
// This function satisfies the plugins.PluginClient interface.
func (p *dcrdataPlugin) Cmd(treeID int64, token []byte, cmd, payload string) (string, error) {
	log.Tracef("dcrdata Cmd: %v %x %v", treeID, token, cmd)

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
// This function satisfies the plugins.PluginClient interface.
func (p *dcrdataPlugin) Hook(treeID int64, token []byte, h plugins.HookT, payload string) error {
	log.Tracef("dcrdata Hook: %v %x %v", treeID, token, plugins.Hooks[h])

	return nil
}

// Fsck performs a plugin filesystem check.
//
// This function satisfies the plugins.PluginClient interface.
func (p *dcrdataPlugin) Fsck(treeIDs []int64) error {
	log.Tracef("dcrdata Fsck")

	return nil
}

// TODO Settings returns the plugin's settings.
//
// This function satisfies the plugins.PluginClient interface.
func (p *dcrdataPlugin) Settings() []backend.PluginSetting {
	log.Tracef("dcrdata Settings")

	return nil
}

func New(settings []backend.PluginSetting, activeNetParams *chaincfg.Params) (*dcrdataPlugin, error) {
	// Unpack plugin settings
	var (
		hostHTTP string
		hostWS   string
	)
	for _, v := range settings {
		switch v.Key {
		case pluginSettingHostHTTP:
			hostHTTP = v.Value
		case pluginSettingHostWS:
			hostWS = v.Value
		default:
			return nil, fmt.Errorf("invalid plugin setting '%v'", v.Key)
		}
	}

	// Set optional plugin settings to default values if a value was
	// not specified.
	if hostHTTP == "" {
		switch activeNetParams.Name {
		case chaincfg.MainNetParams().Name:
			hostHTTP = dcrdata.DefaultHostHTTPMainNet
		case chaincfg.TestNet3Params().Name:
			hostHTTP = dcrdata.DefaultHostHTTPTestNet
		default:
			return nil, fmt.Errorf("unknown active net: %v", activeNetParams.Name)
		}
	}
	if hostWS == "" {
		switch activeNetParams.Name {
		case chaincfg.MainNetParams().Name:
			hostWS = dcrdata.DefaultHostWSMainNet
		case chaincfg.TestNet3Params().Name:
			hostWS = dcrdata.DefaultHostWSTestNet
		default:
			return nil, fmt.Errorf("unknown active net: %v", activeNetParams.Name)
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
