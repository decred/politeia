// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package websockets

import (
	"sync"

	"github.com/gorilla/websocket"
)

// wsContext is the websocket context. If uuid == "" then it is an
// unauthenticated websocket.
type wsContext struct {
	uuid          string
	rid           string
	conn          *websocket.Conn
	wg            sync.WaitGroup
	subscriptions map[string]struct{}
	errorC        chan WSError
	pingC         chan struct{}
	done          chan struct{} // SHUT...DOWN...EVERYTHING...
}

func (w *wsContext) String() string {
	u := w.uuid
	if u == "" {
		u = "anon"
	}
	return u + " " + w.rid
}

// IsAuthenticated returns true if the websocket is authenticated.
func (w *wsContext) isAuthenticated() bool {
	return w.uuid != ""
}
