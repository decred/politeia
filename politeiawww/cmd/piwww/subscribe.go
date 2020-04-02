// Copyright (c) 2017-2019 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http/cookiejar"
	"net/url"
	"os"

	v1 "github.com/thi4go/politeia/politeiawww/api/www/v1"
	"github.com/thi4go/politeia/politeiawww/cmd/shared"
	utilwww "github.com/thi4go/politeia/politeiawww/util"
	"github.com/gorilla/websocket"
	"golang.org/x/net/publicsuffix"
)

// SubscribeCmd opens a websocket connect to politeiawww.
type SubscribeCmd struct {
	Close bool `long:"close" optional:"true"` // Do not keep connetion alive
}

// Execute executes the subscribe command.
func (cmd *SubscribeCmd) Execute(args []string) error {
	// Parse args
	route := v1.RouteUnauthenticatedWebSocket
	subscribe := make([]string, 0, len(args))
	for _, v := range args {
		if v == "auth" {
			route = v1.RouteAuthenticatedWebSocket
			continue
		}
		subscribe = append(subscribe, v)
	}

	// Set cookies
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return err
	}
	u, err := url.Parse(cfg.Host)
	if err != nil {
		return err
	}
	jar.SetCookies(u, cfg.Cookies)

	// Setup websocket
	d := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.SkipVerify,
		},
		Jar: jar,
	}
	uu := url.URL{
		Scheme: "wss",
		Host:   u.Host,
		Path:   v1.PoliteiaWWWAPIRoute + route,
	}
	fmt.Printf("connecting to %s\n", uu.String())

	ws, _, err := d.Dial(uu.String(), nil)
	if err != nil {
		return err
	}
	defer ws.Close()

	err = shared.PrintJSON(v1.WSHeader{Command: v1.WSCSubscribe, ID: "1"})
	if err != nil {
		return err
	}
	err = shared.PrintJSON(v1.WSSubscribe{RPCS: subscribe})
	if err != nil {
		return err
	}

	// Send subscribe command
	err = utilwww.WSWrite(ws, v1.WSCSubscribe, "1", v1.WSSubscribe{
		RPCS: subscribe,
	})
	if err != nil {
		return err
	}

	if cmd.Close {
		return nil
	}

	for {
		_, message, err := ws.ReadMessage()
		if err != nil {
			return err
		}
		var out bytes.Buffer
		err = json.Indent(&out, message, "", "  ")
		if err != nil {
			return err
		}
		out.WriteTo(os.Stdout)
	}

	// not reached
}

// subscribeHelpMsg is the output of the help command when 'subscribe' is
// specified.
const subscribeHelpMsg = `subscribe [auth] <ping...>

Connect and subcribe to www websocket. If auth is provided the connection will
be made to the authenticated websocket (must be logged in).

Flags:
	--close	  (bool, optional)   Do not keep the websocket connection alive

Supported commands:
	- ping (does not require authentication)

Request:
{
}
`
