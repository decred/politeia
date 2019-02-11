package commands

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http/cookiejar"
	"net/url"
	"os"

	v1 "github.com/decred/politeia/politeiawww/api/v1"
	"github.com/decred/politeia/util"
	"github.com/gorilla/websocket"
	"golang.org/x/net/publicsuffix"
)

var SubscribeCmdHelpMsg = `subscribe [auth] <ping...>

Connect and subcribe to www websocket. If auth is provided the connection will
be made to the authenticated websocket (must be logged in).

Supported commands:
	- ping (does not require authentication)

Request:
{
}
`

type Subscribe struct{}

func (cmd *Subscribe) Execute(args []string) error {
	// Check for user identity
	if cfg.Identity == nil {
		return fmt.Errorf(ErrorNoUserIdentity)
	}

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

	err = Print(v1.WSHeader{Command: v1.WSCSubscribe, ID: "1"}, cfg.Verbose,
		cfg.RawJSON)
	if err != nil {
		return err
	}
	err = Print(v1.WSSubscribe{RPCS: subscribe}, cfg.Verbose, cfg.RawJSON)
	if err != nil {
		return err
	}

	// Send subscribe command
	err = util.WSWrite(ws, v1.WSCSubscribe, "1", v1.WSSubscribe{
		RPCS: subscribe,
	})
	if err != nil {
		return err
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
