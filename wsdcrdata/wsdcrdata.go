// Copyright (c) 2019-2020 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

// Package wsdcrdata provides a client for managing dcrdata websocket
// subscriptions.
package wsdcrdata

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/decred/dcrdata/pubsub/v4/psclient"
	"github.com/decred/dcrdata/semver"
)

type StatusT int

const (
	// Websocket statuses
	StatusInvalid      StatusT = 0 // Invalid status
	StatusOpen         StatusT = 1 // Websocket is open
	StatusReconnecting StatusT = 2 // Websocket is attempting to reconnect
	StatusShutdown     StatusT = 3 // Websocket client has been shutdown

	// Pending event actions
	actionSubscribe   = "subscribe"
	actionUnsubscribe = "unsubscribe"

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

	// ErrReconnecting is emitted when attempting to use the Client
	// while it is in the process of reconnecting to dcrdata. All
	// subscribe/unsubscribe actions that are attempted while the
	// client is reconnecting are recorded and completed once the new
	// connection has been made.
	ErrReconnecting = errors.New("reconnecting to dcrdata")

	// ErrShutdown is emitted when attempting to use the Client after
	// it has already been shut down.
	ErrShutdown = errors.New("client is shutdown")
)

// pendingEvent represents an event action (subscribe/unsubscribe) that is
// attempted to be made while the Client is in a StateReconnecting state. The
// pending event actions are replayed in the order in which they were received
// once a new dcrdata connection has been established.
type pendingEvent struct {
	event  string // Websocket event
	action string // Subscribe/unsubscribe
}

// Client is a dcrdata websocket client for managing dcrdata websocket
// subscriptions.
type Client struct {
	sync.Mutex
	url           string
	status        StatusT             // Websocket status
	client        *psclient.Client    // dcrdata websocket client
	subscriptions map[string]struct{} // Active subscriptions

	// pending contains events that were attempted to be subscribed to
	// or unsubscribed from while the client was in a StateReconnecting
	// state. Once a new connection has been established the pending
	// events are replayed in the order in which they were received.
	pending []pendingEvent
}

// statusSet sets the client status.
func (c *Client) statusSet(s StatusT) {
	c.Lock()
	defer c.Unlock()

	c.status = s
}

// clientSet sets the websocket client. The lock is held for this so that the
// golang race detector doesn't complain when the a new client is created and
// set on reconnection attempts.
func (c *Client) clientSet(psc *psclient.Client) {
	c.Lock()
	defer c.Unlock()

	c.client = psc
}

// subAdd adds an event subscription to the subscriptions map.
func (c *Client) subAdd(event string) {
	c.Lock()
	defer c.Unlock()

	c.subscriptions[event] = struct{}{}
}

// subDel removes an event subscription from the subscriptions map.
func (c *Client) subDel(event string) {
	c.Lock()
	defer c.Unlock()

	delete(c.subscriptions, event)
}

// subsGet returns a copy of the full subscriptions list.
func (c *Client) subsGet() map[string]struct{} {
	c.Lock()
	defer c.Unlock()

	s := make(map[string]struct{}, len(c.subscriptions))
	for k := range c.subscriptions {
		s[k] = struct{}{}
	}

	return s
}

// subsDel removes all of the subscriptions from the subscriptions map.
func (c *Client) subsDel() {
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

// pendingAdd adds a pending event to the list of pending events.
func (c *Client) pendingAdd(pe pendingEvent) {
	c.Lock()
	defer c.Unlock()

	c.pending = append(c.pending, pe)
}

// pendingDel deletes the full list of pending events.
func (c *Client) pendingDel() {
	c.Lock()
	defer c.Unlock()

	c.pending = make([]pendingEvent, 0)
}

// pendingGet returns a copy of the pending events list.
func (c *Client) pendingGet() []pendingEvent {
	c.Lock()
	defer c.Unlock()

	p := make([]pendingEvent, 0, len(c.pending))
	p = append(p, c.pending...)

	return p
}

// subscribe subscribes the dcrdata client to an event.
func (c *Client) subscribe(event string) error {
	// Check connection status
	switch c.Status() {
	case StatusShutdown:
		return ErrShutdown
	case StatusReconnecting:
		// Add to list of pending events
		c.pendingAdd(pendingEvent{
			event:  event,
			action: actionSubscribe,
		})
		log.Debugf("Pending event added: subscribe %v", event)
		return ErrReconnecting
	}

	// Ensure subscription doesn't already exist
	if c.isSubscribed(event) {
		return ErrDuplicateSub
	}

	// Subscribe
	_, err := c.client.Subscribe(event)
	if err != nil {
		return fmt.Errorf("wcDcrdata failed to subscribe to %v: %v",
			event, err)
	}

	log.Debugf("Subscribed to %v", event)

	// Update subscriptions list
	c.subAdd(event)

	return nil
}

// unsubscribe ubsubscribes the dcrdata client from an event.
func (c *Client) unsubscribe(event string) error {
	// Check connection status
	switch c.Status() {
	case StatusShutdown:
		return ErrShutdown
	case StatusReconnecting:
		// Add to list of pending events
		c.pendingAdd(pendingEvent{
			event:  event,
			action: actionUnsubscribe,
		})
		log.Debugf("Pending event added: unsubscribe %v", event)
		return ErrReconnecting
	}

	// Ensure subscription exists
	if !c.isSubscribed(event) {
		return ErrSubNotFound
	}

	// Unsubscribe
	_, err := c.client.Unsubscribe(event)
	if err != nil {
		return fmt.Errorf("Client failed to unsubscribe from %v: %v",
			event, err)
	}

	log.Debugf("Unsubscribed from %v", event)

	// Update subscriptions list
	c.subDel(event)

	return nil
}

// Status returns the websocket status.
func (c *Client) Status() StatusT {
	log.Tracef("Status")

	c.Lock()
	defer c.Unlock()

	return c.status
}

// AddressSubscribe subscribes to events for the provided address.
func (c *Client) AddressSubscribe(address string) error {
	log.Tracef("AddressSubscribe: %v", address)

	return c.subscribe(eventAddress + address)
}

// AddressUnsubscribe unsubscribes from events for the provided address.
func (c *Client) AddressUnsubscribe(address string) error {
	log.Tracef("AddressUnsubscribe: %v", address)

	return c.unsubscribe(eventAddress + address)
}

// NewBlockSubscribe subscibes to the new block event.
func (c *Client) NewBlockSubscribe() error {
	log.Tracef("NewBlockSubscribe")

	return c.subscribe(eventNewBlock)
}

// NewBlockUnsubscribe unsubscibes from the new block event.
func (c *Client) NewBlockUnsubscribe() error {
	log.Tracef("NewBlockUnsubscribe")

	return c.unsubscribe(eventNewBlock)
}

// Receive returns a new channel that receives websocket messages from the
// dcrdata server.
func (c *Client) Receive() <-chan *psclient.ClientMessage {
	log.Tracef("Receive")

	// Hold the lock to prevent the go race detector from complaining
	// when the client is switched out on reconnection attempts.
	c.Lock()
	defer c.Unlock()

	return c.client.Receive()
}

// Reconnect creates a new websocket client and subscribes to the same
// subscriptions as the previous client. If a connection cannot be established,
// this function will continue to episodically attempt to reconnect until
// either a connection is made or the application is shut down. If any new
// subscribe/unsubscribe events are registered during this reconnection
// process, they are added to a pending events list and are replayed in the
// order in which they are received once a new connection has been established.
func (c *Client) Reconnect() {
	log.Tracef("Reconnect")

	// Update client status
	c.statusSet(StatusReconnecting)

	// prevSubs is used to track the subscriptions that existed prior
	// to being disconnected so that we can resubscribe to them after
	// establishing a new connection.
	prevSubs := c.subsGet()

	// Clear out disconnected client subscriptions
	c.subsDel()

	// timeToWait specifies the time to wait in between reconnection
	// attempts. This limit is increased if reconnection attempts fail.
	timeToWait := 1 * time.Minute

	// Keep attempting to reconnect until a new connection has been
	// made and all previous subscriptions have been resubscribed to.
	var done bool
	for !done {
		log.Infof("Attempting to reconnect dcrdata websocket")

		// Reconnect to dcrdata
		client, err := psclientNew(c.url)
		if err != nil {
			log.Errorf("New client failed: %v", err)
			goto wait
		}
		c.clientSet(client)

		// Connection open again. Update status.
		c.statusSet(StatusOpen)

		// Resubscribe to previous event subscriptions
		for event := range prevSubs {
			// Ensure not already subscribed
			if c.isSubscribed(event) {
				continue
			}

			// Subscribe
			_, err := c.client.Subscribe(event)
			if err != nil {
				log.Errorf("Failed to subscribe to %v: %v", event, err)
				goto wait
			}

			// Update subscriptions list
			c.subAdd(event)
			log.Debugf("Subscribed to %v", event)
		}

		// Replay any pending event actions that were registered while
		// the client was attempting to reconnect.
		for _, v := range c.pendingGet() {
			switch v.action {
			case actionSubscribe:
				// Ensure not already subscribed
				if c.isSubscribed(v.event) {
					continue
				}

				// Subscribe
				_, err := c.client.Subscribe(v.event)
				if err != nil {
					log.Errorf("Failed to subscribe to %v: %v", v.event, err)
					goto wait
				}

				// Update subscriptions list
				c.subAdd(v.event)
				log.Debugf("Subscribed to %v", v.event)

			case actionUnsubscribe:
				// Ensure not already unsubscribed
				if !c.isSubscribed(v.event) {
					continue
				}

				// Unsubscribe
				_, err := c.client.Unsubscribe(v.event)
				if err != nil {
					log.Errorf("Failed to unsubscribe to %v: %v", v.event, err)
					goto wait
				}

				// Update subscriptions list
				c.subDel(v.event)
				log.Debugf("Unsubscribed from %v", v.event)

			default:
				log.Errorf("unknown pending event action: %v", v.action)
			}
		}

		// Clear out pending events list. These have all been replayed.
		c.pendingDel()

		// We're done!
		done = true
		continue

	wait:
		// Websocket connection is either still closed or closed again
		// before we were able to re-subscribe to all events. Update
		// websocket status and retry again after wait time has elapsed.
		c.statusSet(StatusReconnecting)

		log.Infof("Dcrdata websocket reconnect waiting %v", timeToWait)
		time.Sleep(timeToWait)

		// Increase the wait time until it reaches 15m and then try to
		// reconnect every 15m.
		limit := 15 * time.Minute
		timeToWait *= 2
		if timeToWait > limit {
			timeToWait = limit
		}
	}
}

// Close closes the dcrdata websocket client.
func (c *Client) Close() error {
	log.Tracef("Close")

	// Update websocket status
	c.statusSet(StatusShutdown)

	// Clear out subscriptions list
	c.subsDel()

	// Close connection
	return c.client.Close()
}

func psclientNew(url string) (*psclient.Client, error) {
	opts := psclient.Opts{
		ReadTimeout:  psclient.DefaultReadTimeout,
		WriteTimeout: 3 * time.Second,
	}
	c, err := psclient.New(url, context.Background(), &opts)
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
	clientSemVer := psclient.Version()
	if !semver.Compatible(clientSemVer, serverSemVer) {
		return nil, fmt.Errorf("version mismatch; client %v, server %v",
			serverSemVer, clientSemVer)
	}

	log.Infof("Dcrdata pubsub server version: %v, client version %v",
		serverSemVer, clientSemVer)

	return c, nil
}

// New returns a new Client.
func New(dcrdataURL string) (*Client, error) {
	// Setup dcrdata connection. If there is an error when connecting
	// to dcrdata, return both the error and the Client so that the
	// caller can decide if reconnection attempts should be made.
	var status StatusT
	c, err := psclientNew(dcrdataURL)
	if err == nil {
		// Connection is good
		status = StatusOpen
	} else {
		// Unable to make a connection
		c = &psclient.Client{}
		status = StatusShutdown
	}

	return &Client{
		url:           dcrdataURL,
		status:        status,
		client:        c,
		subscriptions: make(map[string]struct{}),
		pending:       make([]pendingEvent, 0),
	}, err
}
