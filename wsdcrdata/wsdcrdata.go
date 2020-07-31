// Copyright (c) 2019-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package wsdcrdata

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	client "github.com/decred/dcrdata/pubsub/v4/psclient"
	"github.com/decred/dcrdata/semver"
)

const (
	// eventAddress is used to subscribe to events for a specific dcr
	// address. The dcr address must be appended onto the eventAddress
	// string.
	eventAddress = "address:"

	// eventNewBlock is used to subscribe to new block events.
	eventNewBlock = "newblock"
)

var (
	// ErrDuplicateSub is emitted when attempting to subscribe to an
	// event that has already been subscribed to.
	ErrDuplicateSub = errors.New("duplicate subscription")

	// ErrSubNotFound is emitted when attempting to unsubscribe to an
	// event that has not yet been subscribed to.
	ErrSubNotFound = errors.New("subscription not found")

	// ErrShutdown is emitted when attempting to use Client after it
	// has already been shut down.
	ErrShutdown = errors.New("dcrdata ws connection is shut down")
)

// Client is a dcrdata websocket client for managing dcrdata websocket
// subscriptions.
type Client struct {
	sync.Mutex
	shutdown      bool
	client        *client.Client      // dcrdata websocket client
	subscriptions map[string]struct{} // Client subscriptions
	url           string
}

// isShutdown returns whether the connection has been shutdown.
func (c *Client) isShutdown() bool {
	c.Lock()
	defer c.Unlock()

	return c.shutdown
}

// addSub adds an event subscription to the subscriptions map.
func (c *Client) addSub(event string) {
	c.Lock()
	defer c.Unlock()

	c.subscriptions[event] = struct{}{}
}

// removeSub removes an event subscription from the subscriptions map.
func (c *Client) removeSub(event string) {
	c.Lock()
	defer c.Unlock()

	delete(c.subscriptions, event)
}

// removeAllSubs removes all of the subscriptions from the subscriptions map.
func (c *Client) removeAllSubs() {
	c.Lock()
	defer c.Unlock()

	c.subscriptions = make(map[string]struct{})
}

// isSubscribed returns whether the client is subscribed to the provided event.
func (c *Client) isSubscribed(event string) bool {
	c.Lock()
	defer c.Unlock()

	_, ok := c.subscriptions[event]
	return ok
}

// subscribe subscribes the dcrdata client to an event.
func (c *Client) subscribe(event string) error {
	if c.isShutdown() {
		return ErrShutdown
	}

	if c.isSubscribed(event) {
		return ErrDuplicateSub
	}

	_, err := c.client.Subscribe(event)
	if err != nil {
		return fmt.Errorf("wcDcrdata failed to subscribe to %v: %v",
			event, err)
	}

	c.addSub(event)
	log.Debugf("Subscribed to %v", event)
	return nil
}

// unsubscribe ubsubscribes the dcrdata client from an event.
func (c *Client) unsubscribe(event string) error {
	if c.isShutdown() {
		return ErrShutdown
	}

	if !c.isSubscribed(event) {
		return ErrSubNotFound
	}

	_, err := c.client.Unsubscribe(event)
	if err != nil {
		return fmt.Errorf("Client failed to unsubscribe from %v: %v",
			event, err)
	}

	c.removeSub(event)
	log.Debugf("Unsubscribed from %v", event)
	return nil
}

// ping pings the dcrdata server.
func (c *Client) ping() error {
	if c.isShutdown() {
		return ErrShutdown
	}

	return c.client.Ping()
}

// AddressSubscribe subscribes to events for the provided address.
func (c *Client) AddressSubscribe(address string) error {
	log.Tracef("AddressSubscribe: %v", address)

	if c.isShutdown() {
		return ErrShutdown
	}

	return c.subscribe(eventAddress + address)
}

// AddressUnsubscribe unsubscribes from events for the provided address.
func (c *Client) AddressUnsubscribe(address string) error {
	log.Tracef("AddressUnsubscribe: %v", address)

	if c.isShutdown() {
		return ErrShutdown
	}

	return c.unsubscribe(eventAddress + address)
}

// NewBlockSubscribe subscibes to the new block event.
func (c *Client) NewBlockSubscribe() error {
	log.Tracef("NewBlockSubscribe")

	if c.isShutdown() {
		return ErrShutdown
	}

	return c.subscribe(eventNewBlock)
}

// NewBlockUnsubscribe unsubscibes from the new block event.
func (c *Client) NewBlockUnsubscribe() error {
	log.Tracef("NewBlockUnsubscribe")

	if c.isShutdown() {
		return ErrShutdown
	}

	return c.unsubscribe(eventNewBlock)
}

// Receive returns a new channel that receives websocket messages from the
// dcrdata server.
func (c *Client) Receive() (<-chan *client.ClientMessage, error) {
	log.Tracef("Receive")

	if c.isShutdown() {
		return nil, ErrShutdown
	}

	return c.client.Receive(), nil
}

// Reconnect creates a new websocket client and subscribes to the same
// subscriptions as the previous client. If a connection cannot be established,
// this function will continue to episodically attempt to reconnect until
// either a connection is made or the application is shut down.
func (c *Client) Reconnect() error {
	log.Tracef("Reconnect")

	if c.isShutdown() {
		return ErrShutdown
	}

	// prevSubs is used to track the subscriptions that existed prior
	// to being disconnected so that we can resubscribe to them after
	// establishing a new connection.
	prevSubs := make(map[string]struct{}, len(c.subscriptions))

	// timeToWait specifies the time to wait in between reconnection
	// attempts.
	timeToWait := 1 * time.Minute

	// Keep attempting to reconnect until a new connection has been
	// made and all previous subscriptions have been resubscribed to.
	var done bool
	for !done {
		log.Infof("Attempting to reconnect dcrdata websocket")

		// Stop the client just to be sure
		c.client.Stop()

		// Remove any existing subscriptions since these are no longer
		// active. These will be resubscribed to.
		for sub := range c.subscriptions {
			prevSubs[sub] = struct{}{}
		}
		c.removeAllSubs()

		// Reconnect to dcrdata
		client, err := newDcrdataWSClient(c.url)
		if err != nil {
			log.Errorf("New client failed: %v", err)
			goto wait
		}
		c.client = client

		// Resubscribe to events
		for sub := range prevSubs {
			if c.isSubscribed(sub) {
				delete(prevSubs, sub)
				continue
			}
			_, err := c.client.Subscribe(sub)
			if err != nil {
				log.Errorf("Failed to subscribe to %v: %v", sub, err)
				goto wait
			}
			c.addSub(sub)
			delete(prevSubs, sub)
		}

		// We're done!
		done = true
		continue

	wait:
		log.Infof("Dcrdata websocket reconnect waiting %v", timeToWait)

		// Increase wait time until it reaches an hour then try to
		// reconnect once per hour.
		time.Sleep(timeToWait)
		timeToWait = 2 * timeToWait
		if timeToWait > time.Hour {
			timeToWait = time.Hour
		}
	}

	return nil
}

func newDcrdataWSClient(url string) (*client.Client, error) {
	opts := client.Opts{
		ReadTimeout:  client.DefaultReadTimeout,
		WriteTimeout: 3 * time.Second,
	}
	c, err := client.New(url, context.Background(), &opts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %v: %v", url, err)
	}

	log.Infof("Dcrdata websocket host: %v", url)

	// Check client and server compatibility
	v, err := c.ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("server version failed: %v", err)
	}
	serverSemVer := semver.NewSemver(v.Major, v.Minor, v.Patch)
	clientSemVer := client.Version()
	if !semver.Compatible(clientSemVer, serverSemVer) {
		return nil, fmt.Errorf("version mismatch; client %v, server %v",
			serverSemVer, clientSemVer)
	}

	log.Infof("Dcrdata pubsub server version: %v, client version %v",
		serverSemVer, clientSemVer)

	return c, nil
}

// Close closes the dcrdata websocket client.
func (c *Client) Close() error {
	log.Tracef("Close")

	c.Lock()
	c.shutdown = true
	c.Unlock()

	c.removeAllSubs()
	return c.client.Close()
}

// New returns a new Client.
func New(dcrdataURL string) (*Client, error) {
	client, err := newDcrdataWSClient(dcrdataURL)
	if err != nil {
		return nil, err
	}

	return &Client{
		client:        client,
		subscriptions: make(map[string]struct{}),
		url:           dcrdataURL,
	}, nil
}
