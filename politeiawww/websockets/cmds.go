// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package websockets

// Websocket commands
const (
	WSCError     = "error"
	WSCPing      = "ping"
	WSCSubscribe = "subscribe"
)

// WSHeader is required to be sent before any other command. The point is to
// make decoding easier without too much magic. E.g. a ping command
// WSHeader<ping>WSPing<timestamp>
type WSHeader struct {
	Command string `json:"command"`      // Following command
	ID      string `json:"id,omitempty"` // Client setable client id
}

// WSError is a generic websocket error. It returns in ID the client side id
// and all errors it encountered in Errors.
type WSError struct {
	Command string   `json:"command,omitempty"` // Command from client
	ID      string   `json:"id,omitempty"`      // Client set client id
	Errors  []string `json:"errors"`            // Errors returned by server
}

// WSSubscribe is a client side push to tell the server what RPCs it wishes to
// subscribe to.
type WSSubscribe struct {
	RPCS []string `json:"rpcs"` // Commands that the client wants to subscribe to
}

// WSPing is a server side push to the client to see if it is still alive.
type WSPing struct {
	Timestamp int64 `json:"timestamp"` // Server side timestamp
}
