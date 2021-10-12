// Copyright (c) 2017-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package websockets

import (
	"encoding/json"
	"errors"

	"github.com/gorilla/websocket"
)

var (
	// ErrInvalidWSCommand is returned when an invalid command is attempted to be
	// written to a websocket connection or when an invalid message or command is
	// read from a websocket connection.
	ErrInvalidWSCommand = errors.New("invalid webssocket command")
)

// Write writes a command to the websocket connection. A WSHeader is written to
// the connection prior to sending the command payload.
func Write(c *websocket.Conn, cmd, id string, payload interface{}) error {
	if !validCommand(cmd) {
		return ErrInvalidWSCommand
	}
	err := c.WriteJSON(WSHeader{Command: cmd, ID: id})
	if err != nil {
		return err
	}
	return c.WriteJSON(payload)
}

// Read reads a command from the websocket connection. Reads are performed in
// two steps. First, a WSHeader is read from the connection. If a valid header
// is found then the command payload is read and returned.
func Read(c *websocket.Conn) (string, string, interface{}, error) {
	var header WSHeader
	err := c.ReadJSON(&header)
	if err != nil {
		return "", "", nil, err
	}

	var payload interface{}
	switch header.Command {
	case WSCSubscribe:
		var subscribe WSSubscribe
		err = c.ReadJSON(&subscribe)
		payload = subscribe
	case WSCPing:
		var ping WSPing
		err = c.ReadJSON(&ping)
		payload = ping
	default:
		return "", "", nil, ErrInvalidWSCommand
	}

	return header.Command, header.ID, payload, err
}

// validCommand returns whether the command is a valid command.
func validCommand(cmd string) bool {
	switch cmd {
	case WSCError:
	case WSCPing:
	case WSCSubscribe:
	default:
		return false
	}
	return true
}

// ValidSubcription returns whether the command is a valid client subscription.
func ValidSubscription(cmd string) bool {
	switch cmd {
	case WSCPing:
	default:
		return false
	}
	return true
}

// SubscriptionReqAuth returns whether the command requires the client to be
// authenticated.
func SubsciptionReqAuth(cmd string) bool {
	switch cmd {
	case WSCPing:
	default:
		return true
	}
	return false
}

// WSJSON returns the JSON representation of a wire command. This function must
// always match WSWrite.
func WSJSON(cmd, id string, payload interface{}) ([][]byte, error) {
	j1, err := json.Marshal(WSHeader{Command: cmd, ID: id})
	if err != nil {
		return nil, err
	}
	j2, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	r := make([][]byte, 2)
	r[0] = j1
	r[1] = j2
	return r, nil
}
