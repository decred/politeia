package main

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
	errShutdown = errors.New("dcrdata ws connection is shut down")
)

// wsDcrdata is the context used for managing a dcrdata websocket connection.
type wsDcrdata struct {
	sync.RWMutex
	shutdown      bool
	client        *client.Client      // dcrdata websocket client
	subscriptions map[string]struct{} // Client subscriptions
	url           string
}

// isShutdown returns whether the connection has been shutdown.
func (w *wsDcrdata) isShutdown() bool {
	w.RLock()
	defer w.RUnlock()

	return w.shutdown
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
	w.RLock()
	defer w.RUnlock()

	_, ok := w.subscriptions[event]
	return ok
}

// close closes the dcrdata websocket client.
func (w *wsDcrdata) close() error {
	w.Lock()
	w.shutdown = true
	w.Unlock()

	w.removeAllSubs()
	return w.client.Close()
}

// subscribe subscribes the dcrdata client to an event.
func (w *wsDcrdata) subscribe(event string) error {
	if w.isShutdown() {
		return errShutdown
	}

	if w.isSubscribed(event) {
		return errDuplicateSub
	}

	_, err := w.client.Subscribe(event)
	if err != nil {
		return fmt.Errorf("wcDcrdata failed to subscribe to %v: %v",
			event, err)
	}

	w.addSub(event)
	log.Debugf("wsDcrdata successfully subscribed to %v", event)
	return nil
}

// unsubscribe ubsubscribes the dcrdata client from an event.
func (w *wsDcrdata) unsubscribe(event string) error {
	if w.isShutdown() {
		return errShutdown
	}

	if !w.isSubscribed(event) {
		return errSubNotFound
	}

	_, err := w.client.Unsubscribe(event)
	if err != nil {
		return fmt.Errorf("wsDcrdata failed to unsubscribe from %v: %v",
			event, err)
	}

	w.removeSub(event)
	log.Debugf("wsDcrdata successfully unsubscribed from %v", event)
	return nil
}

func (w *wsDcrdata) receive() (<-chan *client.ClientMessage, error) {
	if w.isShutdown() {
		return nil, errShutdown
	}

	return w.client.Receive(), nil
}

// ping pings the dcrdata server.
func (w *wsDcrdata) ping() error {
	if w.isShutdown() {
		return errShutdown
	}

	return w.client.Ping()
}

func (w *wsDcrdata) subToAddr(address string) error {
	return w.subscribe(addrSubPrefix + address)
}

func (w *wsDcrdata) unsubFromAddr(address string) error {
	return w.unsubscribe(addrSubPrefix + address)
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

// reconnect creates a new websocket client, and subscribes to the
// same subscriptions as the previous client.
func (w *wsDcrdata) reconnect() error {
	if w.isShutdown() {
		return errShutdown
	}

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
		err := w.ping()
		if err == errShutdown {
			return errShutdown
		} else if err != nil {
			log.Errorf("wsDcrdata failed to ping dcrdata: %v", err)
			w.client.Stop()

			// Existing subscriptions have gone bad
			for sub := range w.subscriptions {
				prevSubscriptions[sub] = struct{}{}
			}
			w.removeAllSubs()

			// Reconnect
			c, err := newDcrdataWSClient(w.url)
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
			// Increase wait time until it reaches an hour then
			// try to reconnect once per hour.
			timeToWait = 2 * timeToWait
			if timeToWait > time.Hour {
				timeToWait = time.Hour
			}
		}
	}

	return nil
}

// newWSDcrdata return a new wsDcrdata context.
func (p *politeiawww) newWSDcrdata() (*wsDcrdata, error) {
	client, err := newDcrdataWSClient(p.dcrdataWsApi())
	if err != nil {
		return nil, err
	}

	return &wsDcrdata{
		client:        client,
		subscriptions: make(map[string]struct{}),
		url:           p.dcrdataWsApi(),
	}, nil
}
