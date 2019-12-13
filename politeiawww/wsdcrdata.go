package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	client "github.com/decred/dcrdata/pubsub/v3/psclient"
	"github.com/decred/dcrdata/semver"
	"github.com/decred/politeia/util"
)

const (
	// addrSubPrefix must be prefixed to the address when subscribing
	// to address events.
	addrSubPrefix = "address:"

	// newBlockSub subscribes to events which give information about
	// each new block
	newBlockSub = "newblock"
)

var (
	// errDuplicateSub is emitted when attempting to subscribe to an
	// event that has already been subscribed to.
	errDuplicateSub = errors.New("duplicate subscription")

	// errSubNotFound is emitted when attempting to unsubscribe to an
	// event that has not yet been subscribed to.
	errSubNotFound = errors.New("subscription not found")

	// errShutdown is emitted when attempting to use wsDcrdata after it
	// has already been shut down.
	errShutdown = errors.New("ws connection is shut down")
)

// wsDcrdata is the context used for managing a dcrdata websocket connection.
type wsDcrdata struct {
	sync.RWMutex
	shutdown      bool
	client        *client.Client      // dcrdata websocket client
	subscriptions map[string]struct{} // Client subscriptions
	recvMsgChan   chan *client.ClientMessage
}

// isShutdown returns whether the connection has been shutdown.
func (w *wsDcrdata) isShutdown() bool {
	w.RLock()
	defer w.RUnlock()

	return w.shutdown
}

func (w *wsDcrdata) Receive() <-chan *client.ClientMessage {
	return w.recvMsgChan
}

// This type of message is sent to notify listeners that the context is being
// shut down.
type wsDcrdataShutdown struct{}

// close closes the dcrdata websocket client and lets listeners know that this is happening.
func (w *wsDcrdata) close() error {
	w.Lock()
	defer w.Unlock()

	w.shutdown = true
	w.recvMsgChan <- &client.ClientMessage{
		Message: wsDcrdataShutdown{},
	}

	return w.client.Close()
}

// addSub adds an event subscription to the subscriptions map.
func (w *wsDcrdata) addSub(event string) {
	w.Lock()
	defer w.Unlock()

	w.subscriptions[event] = struct{}{}
}

// removeSub removes an event subscription from the subscriptions map.
func (w *wsDcrdata) removeSub(event string) {
	w.Lock()
	defer w.Unlock()

	delete(w.subscriptions, event)
}

// removeAllSubs removes all of the subscriptions from the subscriptions map.
func (w *wsDcrdata) removeAllSubs() {
	w.Lock()
	defer w.Unlock()

	w.subscriptions = make(map[string]struct{})
}

// isSubscribed returns whether the client is subscribed to the provided event.
func (w *wsDcrdata) isSubscribed(event string) bool {
	if w.isShutdown() {
		return false
	}

	w.RLock()
	defer w.RUnlock()

	_, ok := w.subscriptions[event]
	return ok
}

// subToAddr subscribes to dcrdata events for the provided address.
func (w *wsDcrdata) subToAddr(address string) error {
	if w.isShutdown() {
		return errShutdown
	}

	event := addrSubPrefix + address
	if w.isSubscribed(event) {
		return errDuplicateSub
	}
	_, err := w.client.Subscribe(event)
	if err != nil {
		return fmt.Errorf("wcDcrdata failed to subscribe to %v: %v",
			event, err)
	}
	w.addSub(event)
	log.Debugf("wsDcrdata subscribed to addr: %v", address)
	return nil
}

// unsubFromAddr unsubscribes from dcrdata events for the provided address.
func (w *wsDcrdata) unsubFromAddr(address string) error {
	if w.isShutdown() {
		return errShutdown
	}

	event := addrSubPrefix + address
	if !w.isSubscribed(event) {
		return errSubNotFound
	}
	_, err := w.client.Unsubscribe(event)
	if err != nil {
		return fmt.Errorf("wsDcrdata failed to unsubscribe from %v: %v",
			event, err)
	}
	w.removeSub(event)
	log.Debugf("wsDcrdata unsubscribed from addr: %v", address)
	return nil
}

// subToNewBlock subscribes to dcrdata events for new blocks
func (w *wsDcrdata) subToNewBlock() error {
	if w.isShutdown() {
		return errShutdown
	}

	if w.isSubscribed(newBlockSub) {
		return errDuplicateSub
	}
	_, err := w.client.Subscribe(newBlockSub)
	if err != nil {
		return fmt.Errorf("wsDcrdata failed to subscribe to %v: %v",
			newBlockSub, err)
	}
	w.addSub(newBlockSub)
	log.Debugf("wsDcrdata subscribed to new block")
	return nil
}

// newRecvMsgChan returns a channel to which the dcrdata client's messages are
// forwarded. This way, wsDcrdata can send messages of its own to its clients.
func newRecvMsgChan(c *client.Client) chan *client.ClientMessage {
	recvMsgChan := make(chan *client.ClientMessage, 16)
	go func() {
		for {
			msg := <-c.Receive()
			recvMsgChan <- msg
		}
	}()
	return recvMsgChan
}

func newDcrdataWSClient() (*client.Client, error) {
	u, err := util.BlockExplorerURLForSubscriptions(activeNetParams.Params)
	if err != nil {
		return nil, err
	}
	opts := client.Opts{
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}
	c, err := client.New(u, context.Background(), &opts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %v: %v", u, err)
	}

	log.Infof("Dcrdata websocket host: %v", u)

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

// reconnect creates a new websocket client, and subscribes to the
// same subscriptions as the previous client.
func (w *wsDcrdata) reconnect() error {
	if w.isShutdown() {
		log.Errorf("wsDcrdata is shutdown, not reconnecting")
		return errShutdown
	}

	done := make(chan struct{})

	go func() {
		prevSubscriptions := make(map[string]struct{}, len(w.subscriptions))
		timeToWait := 1 * time.Minute

		// Remove existing subscriptions since the client is
		// no longer connected. These will be resubscribed to.
		w.client.Stop()
		for sub := range w.subscriptions {
			prevSubscriptions[sub] = struct{}{}
		}
		w.removeAllSubs()

		for len(prevSubscriptions) > 0 {
			// Reconnect to dcrdata if needed
			err := w.client.Ping()
			if err != nil {
				w.client.Stop()

				// Existing subscriptions have gone bad
				for sub := range w.subscriptions {
					prevSubscriptions[sub] = struct{}{}
				}
				w.removeAllSubs()

				// Reconnect
				c, err := newDcrdataWSClient()
				w.recvMsgChan = newRecvMsgChan(c)
				if err != nil {
					log.Errorf("wsDcrdata failed to create new client while "+
						"reconnecting: %v", err)
					goto wait
				}
				w.client = c
			}

			// Resubscribe
			for sub := range prevSubscriptions {
				if w.isSubscribed(sub) {
					delete(prevSubscriptions, sub)
					continue
				}
				_, err := w.client.Subscribe(sub)
				if err != nil {
					log.Errorf("wsDcrdata failed to subscribe to %v: %v",
						sub, err)
					goto wait
				}
				w.addSub(sub)
				delete(prevSubscriptions, sub)
			}

		wait:
			if len(prevSubscriptions) > 0 {
				log.Debugf("wsDcrdata reconnect waiting %v", timeToWait)
				time.Sleep(timeToWait)
				timeToWait = 2 * timeToWait
			}
		}

		// All previous subscriptions have been re-subscribed
		// to. We're done.
		done <- struct{}{}
	}()

	<-done
	return nil
}

// newWSDcrdata return a new wsDcrdata context.
func newWSDcrdata() (*wsDcrdata, error) {
	client, err := newDcrdataWSClient()
	if err != nil {
		return nil, err
	}

	return &wsDcrdata{
		client:        client,
		subscriptions: make(map[string]struct{}),
		recvMsgChan:   newRecvMsgChan(client),
	}, nil
}
