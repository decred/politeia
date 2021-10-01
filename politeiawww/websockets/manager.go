// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package websockets

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/decred/politeia/util"
	"github.com/gorilla/websocket"
)

// Manager provides an API for managing websocket connections.
//
// NOTE: this memory store needs to be replaced by a data store that allows for
// horizontal scaling.
type Manager struct {
	sync.RWMutex
	readLimit int64 // Max allowed bytes for msg reads

	ws map[string]map[string]*wsContext // [uuid][]*wsContext
}

// NewManager returns a new websocket Manager.
func NewManager(readLimit int64) *Manager {
	return &Manager{
		readLimit: readLimit,
		ws:        make(map[string]map[string]*wsContext),
	}
}

// HandleWebsocket upgrades a regular HTTP connection to a websocket.
func (m *Manager) HandleWebsocket(w http.ResponseWriter, r *http.Request, id string) {
	log.Tracef("handleWebsocket: %v", id)
	defer log.Tracef("handleWebsocket exit: %v", id)

	// Setup context
	wc := wsContext{
		uuid:          id,
		subscriptions: make(map[string]struct{}),
		pingC:         make(chan struct{}),
		errorC:        make(chan WSError),
		done:          make(chan struct{}),
	}

	var upgrader = websocket.Upgrader{
		EnableCompression: true,
	}

	var err error
	wc.conn, err = upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, "Could not open websocket connection",
			http.StatusBadRequest)
		return
	}
	defer wc.conn.Close() // causes read to exit as well

	// Set connection read limit
	wc.conn.SetReadLimit(m.readLimit)

	// Create and assign session to map
	m.Lock()
	if _, ok := m.ws[id]; !ok {
		m.ws[id] = make(map[string]*wsContext)
	}
	for {
		rid, err := util.Random(16)
		if err != nil {
			m.Unlock()
			http.Error(w, "Could not create random session id",
				http.StatusBadRequest)
			return
		}
		wc.rid = hex.EncodeToString(rid)
		if _, ok := m.ws[id][wc.rid]; !ok {
			break
		}
	}
	m.ws[id][wc.rid] = &wc
	m.Unlock()

	// Reads
	wc.wg.Add(1)
	go m.handleWebsocketRead(&wc)

	// Writes
	wc.wg.Add(1)
	go m.handleWebsocketWrite(&wc)

	// XXX Example of a server side notification. Remove once other commands
	// can be used as examples.
	// time.Sleep(2 * time.Second)
	// p.websocketPing(id)

	wc.wg.Wait()

	// Remove session id
	m.Lock()
	delete(m.ws[id], wc.rid)
	if len(m.ws[id]) == 0 {
		// Remove uuid since it was the last one
		delete(m.ws, id)
	}
	m.Unlock()
}

// handleWebsocketRead reads a websocket command off the socket and tries to
// handle it. Currently it only supports subscribing to websocket events.
func (m *Manager) handleWebsocketRead(wc *wsContext) {
	defer wc.wg.Done()

	log.Tracef("handleWebsocketRead %v", wc)
	defer log.Tracef("handleWebsocketRead exit %v", wc)

	for {
		cmd, id, payload, err := Read(wc.conn)
		if err != nil {
			log.Tracef("handleWebsocketRead read %v %v", wc, err)
			close(wc.done) // force handlers to quit
			return
		}
		switch cmd {
		case WSCSubscribe:
			subscribe, ok := payload.(WSSubscribe)
			if !ok {
				// We are treating this a hard error so that
				// the client knows they sent in something
				// wrong.
				log.Errorf("handleWebsocketRead invalid "+
					"subscribe type %v %v", wc,
					spew.Sdump(payload))
				return
			}

			//log.Tracef("subscribe: %v %v", wc.uuid,
			//	spew.Sdump(subscribe))

			subscriptions := make(map[string]struct{})
			var errors []string
			for _, v := range subscribe.RPCS {
				if !ValidSubscription(v) {
					log.Tracef("invalid subscription %v %v",
						wc, v)
					errors = append(errors,
						fmt.Sprintf("invalid "+
							"subscription %v", v))
					continue
				}
				if SubsciptionReqAuth(v) &&
					!wc.isAuthenticated() {
					log.Tracef("requires auth %v %v", wc, v)
					errors = append(errors,
						fmt.Sprintf("requires "+
							"authentication %v", v))
					continue
				}
				subscriptions[v] = struct{}{}
			}

			if len(errors) == 0 {
				// Replace old subscriptions
				m.Lock()
				wc.subscriptions = subscriptions
				m.Unlock()
			} else {
				wc.errorC <- WSError{
					Command: WSCSubscribe,
					ID:      id,
					Errors:  errors,
				}
			}
		}
	}
}

// handleWebsocketWrite attempts to notify a subscribed websocket. Currently
// only ping is supported.
func (m *Manager) handleWebsocketWrite(wc *wsContext) {
	defer wc.wg.Done()
	log.Tracef("handleWebsocketWrite %v", wc)
	defer log.Tracef("handleWebsocketWrite exit %v", wc)

	for {
		var (
			cmd, id string
			payload interface{}
		)
		select {
		case <-wc.done:
			return
		case e, ok := <-wc.errorC:
			if !ok {
				log.Tracef("handleWebsocketWrite error not ok"+
					" %v", wc)
				return
			}
			cmd = WSCError
			id = e.ID
			payload = e
		case _, ok := <-wc.pingC:
			if !ok {
				log.Tracef("handleWebsocketWrite ping not ok"+
					" %v", wc)
				return
			}
			cmd = WSCPing
			id = ""
			payload = WSPing{Timestamp: time.Now().Unix()}
		}

		err := Write(wc.conn, cmd, id, payload)
		if err != nil {
			log.Tracef("handleWebsocketWrite write %v %v", wc, err)
			return
		}
	}
}

// websocketPing is used to verify that websockets are operational.
func (m *Manager) ping(id string) {
	log.Tracef("ping %v", id)
	defer log.Tracef("ping exit %v", id)

	m.RLock()
	defer m.RUnlock()

	for _, v := range m.ws[id] {
		if _, ok := v.subscriptions[WSCPing]; !ok {
			continue
		}

		select {
		case v.pingC <- struct{}{}:
		default:
		}
	}
}
