// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"fmt"
	"net/http"

	cmplugin "github.com/decred/politeia/politeiad/plugins/comments"
	piplugin "github.com/decred/politeia/politeiad/plugins/pi"
	tkplugin "github.com/decred/politeia/politeiad/plugins/ticketvote"
	usplugin "github.com/decred/politeia/politeiad/plugins/user"
	piv1 "github.com/decred/politeia/politeiawww/api/pi/v1"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
)

// ErrorReply represents the request body that is returned from politeiawww
// when an error occurs. PluginID will only be populated if the error occured
// during execution of a plugin command.
type ErrorReply struct {
	PluginID     string
	ErrorCode    int
	ErrorContext string
}

// Error represents a politeiawww response error. An Error is returned anytime
// the politeiawww response is not a 200.
type Error struct {
	HTTPCode   int
	API        string
	ErrorReply ErrorReply
}

// Error satisfies the error interface.
func (e Error) Error() string {
	switch e.HTTPCode {
	case http.StatusInternalServerError:
		return fmt.Sprintf("500 internal server error: %v",
			e.ErrorReply.ErrorCode)
	case http.StatusBadRequest:
		var msg string
		if e.ErrorReply.PluginID == "" {
			// API user error
			msg = apiUserErr(e.API, e.ErrorReply)
		} else {
			// Plugin user error
			msg = pluginUserErr(e.ErrorReply)
		}
		return fmt.Sprintf("%v %v", e.HTTPCode, msg)
	default:
		return fmt.Sprintf("%v %+v", e.HTTPCode, e.ErrorReply)
	}
}

func apiUserErr(api string, e ErrorReply) string {
	var errMsg string
	switch api {
	case piv1.APIRoute:
		errMsg = piv1.ErrorCodes[piv1.ErrorCodeT(e.ErrorCode)]
	case rcv1.APIRoute:
		errMsg = rcv1.ErrorCodes[rcv1.ErrorCodeT(e.ErrorCode)]
	case tkv1.APIRoute:
		errMsg = tkv1.ErrorCodes[tkv1.ErrorCodeT(e.ErrorCode)]
	}
	m := fmt.Sprintf("user error code %v", e.ErrorCode)
	if errMsg != "" {
		m += fmt.Sprintf(", %v", errMsg)
	}
	if e.ErrorContext != "" {
		m += fmt.Sprintf(": %v", e.ErrorContext)
	}
	return m
}

func pluginUserErr(e ErrorReply) string {
	var errMsg string
	switch e.PluginID {
	case cmplugin.PluginID:
		errMsg = cmplugin.ErrorCodes[cmplugin.ErrorCodeT(e.ErrorCode)]
	case piplugin.PluginID:
		errMsg = piplugin.ErrorCodes[piplugin.ErrorCodeT(e.ErrorCode)]
	case tkplugin.PluginID:
		errMsg = tkplugin.ErrorCodes[tkplugin.ErrorCodeT(e.ErrorCode)]
	case usplugin.PluginID:
		errMsg = usplugin.ErrorCodes[usplugin.ErrorCodeT(e.ErrorCode)]
	}
	m := fmt.Sprintf("%v plugin error code %v", e.PluginID, e.ErrorCode)
	if errMsg != "" {
		m += fmt.Sprintf(", %v", errMsg)
	}
	if e.ErrorContext != "" {
		m += fmt.Sprintf(": %v", e.ErrorContext)
	}
	return m
}
