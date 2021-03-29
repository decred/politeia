// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package client

import (
	"fmt"
	"net/http"
	"strings"

	cmplugin "github.com/decred/politeia/politeiad/plugins/comments"
	piplugin "github.com/decred/politeia/politeiad/plugins/pi"
	tkplugin "github.com/decred/politeia/politeiad/plugins/ticketvote"
	umplugin "github.com/decred/politeia/politeiad/plugins/usermd"
	cmv1 "github.com/decred/politeia/politeiawww/api/comments/v1"
	rcv1 "github.com/decred/politeia/politeiawww/api/records/v1"
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
)

// ErrorReply represents the request body that is returned from politeiawww
// when an error occurs. PluginID will only be populated if the error occurred
// during execution of a plugin command.
type ErrorReply struct {
	PluginID     string
	ErrorCode    int
	ErrorContext string
}

// RespErr represents a politeiawww response error. A RespErr is returned
// anytime the politeiawww response is not a 200.
//
// The various politeiawww APIs can have overlapping error codes. The API is
// included to allow the Error() method to return the correct human readable
// error message.
type RespErr struct {
	HTTPCode   int
	API        string
	ErrorReply ErrorReply
}

// Error satisfies the error interface.
func (e RespErr) Error() string {
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
	case cmv1.APIRoute:
		errMsg = cmv1.ErrorCodes[cmv1.ErrorCodeT(e.ErrorCode)]
	case rcv1.APIRoute:
		errMsg = rcv1.ErrorCodes[rcv1.ErrorCodeT(e.ErrorCode)]
	case tkv1.APIRoute:
		errMsg = tkv1.ErrorCodes[tkv1.ErrorCodeT(e.ErrorCode)]
	}

	// Remove "/" from api string. "/records/v1" to "records v1".
	s := strings.Split(api, "/")
	api = strings.Join(s, " ")
	api = strings.Trim(api, " ")

	// Create error string
	m := fmt.Sprintf("%v user error code %v", api, e.ErrorCode)
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
	case umplugin.PluginID:
		errMsg = umplugin.ErrorCodes[umplugin.ErrorCodeT(e.ErrorCode)]
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
