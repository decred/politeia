// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

import (
	"encoding/json"
	"errors"

	v1 "github.com/thi4go/politeia/politeiawww/api/www/v1"
	"github.com/gorilla/websocket"
)

var (
	ErrInvalidWSCommand = errors.New("invalid webssocket command")
)

func validCommand(cmd string) bool {
	switch cmd {
	case v1.WSCError:
	case v1.WSCPing:
	case v1.WSCSubscribe:
	default:
		return false
	}
	return true
}

func ValidSubscription(cmd string) bool {
	switch cmd {
	case v1.WSCPing:
	default:
		return false
	}
	return true
}

func SubsciptionReqAuth(cmd string) bool {
	switch cmd {
	case v1.WSCPing:
	default:
		return true
	}
	return false
}

// WSJSON returns the JSON representation of a wire command. This function must
// always match WSWrite.
func WSJSON(cmd, id string, payload interface{}) ([][]byte, error) {
	j1, err := json.Marshal(v1.WSHeader{Command: cmd, ID: id})
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

func WSWrite(c *websocket.Conn, cmd, id string, payload interface{}) error {
	if !validCommand(cmd) {
		return ErrInvalidWSCommand
	}
	err := c.WriteJSON(v1.WSHeader{Command: cmd, ID: id})
	if err != nil {
		return err
	}
	return c.WriteJSON(payload)
}

func WSRead(c *websocket.Conn) (string, string, interface{}, error) {
	var header v1.WSHeader
	err := c.ReadJSON(&header)
	if err != nil {
		return "", "", nil, err
	}

	var payload interface{}
	switch header.Command {
	case v1.WSCSubscribe:
		var subscribe v1.WSSubscribe
		err = c.ReadJSON(&subscribe)
		payload = subscribe
	case v1.WSCPing:
		var ping v1.WSPing
		err = c.ReadJSON(&ping)
		payload = ping
	default:
		return "", "", nil, ErrInvalidWSCommand
	}

	return header.Command, header.ID, payload, err
}
