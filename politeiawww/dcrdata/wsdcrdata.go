package dcrdata

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
	// AddrSubPrefix must be prefixed to the address when subscribing
	// to address events.
	AddrSubPrefix = "address:"

	// NewBlockSub subscribes to events which give information about
	// each new block
	NewBlockSub = "newblock"
)

var (
	// ErrDuplicateSub is emitted when attempting to subscribe to an
	// event that has already been subscribed to.
	ErrDuplicateSub = errors.New("duplicate subscription")

	// ErrSubNotFound is emitted when attempting to unsubscribe to an
	// event that has not yet been subscribed to.
	ErrSubNotFound = errors.New("subscription not found")

	// ErrShutdown is emitted when attempting to use WSDcrdata after it
	// has already been shut down.
	ErrShutdown = errors.New("dcrdata ws connection is shut down")
)

// WSDcrdata is the context used for managing a dcrdata websocket connection.
type WSDcrdata struct {
	sync.RWMutex
	shutdown      bool
	client        *client.Client      // dcrdata websocket client
	subscriptions map[string]struct{} // Client subscriptions
	url           string
}

// IsShutdown returns whether the connection has been shutdown.
func (w *WSDcrdata) IsShutdown() bool {
	w.RLock()
	defer w.RUnlock()

	return w.shutdown
}

// addSub adds an event subscription to the subscriptions map.
func (w *WSDcrdata) addSub(event string) {
	w.Lock()
	defer w.Unlock()

	w.subscriptions[event] = struct{}{}
}

// removeSub removes an event subscription from the subscriptions map.
func (w *WSDcrdata) removeSub(event string) {
	w.Lock()
	defer w.Unlock()

	delete(w.subscriptions, event)
}

// removeAllSubs removes all of the subscriptions from the subscriptions map.
func (w *WSDcrdata) removeAllSubs() {
	w.Lock()
	defer w.Unlock()

	w.subscriptions = make(map[string]struct{})
}

// isSubscribed returns whether the client is subscribed to the provided event.
func (w *WSDcrdata) isSubscribed(event string) bool {
	w.RLock()
	defer w.RUnlock()

	_, ok := w.subscriptions[event]
	return ok
}

// Close closes the dcrdata websocket client.
func (w *WSDcrdata) Close() error {
	w.Lock()
	w.shutdown = true
	w.Unlock()

	w.removeAllSubs()
	return w.client.Close()
}

// Subscribe subscribes the dcrdata client to an event.
func (w *WSDcrdata) Subscribe(event string) error {
	if w.IsShutdown() {
		return ErrShutdown
	}

	if w.isSubscribed(event) {
		return ErrDuplicateSub
	}

	_, err := w.client.Subscribe(event)
	if err != nil {
		return fmt.Errorf("wcDcrdata failed to subscribe to %v: %v",
			event, err)
	}

	w.addSub(event)
	log.Debugf("WSDcrdata successfully subscribed to %v", event)
	return nil
}

// unsubscribe ubsubscribes the dcrdata client from an event.
func (w *WSDcrdata) unsubscribe(event string) error {
	if w.IsShutdown() {
		return ErrShutdown
	}

	if !w.isSubscribed(event) {
		return ErrSubNotFound
	}

	_, err := w.client.Unsubscribe(event)
	if err != nil {
		return fmt.Errorf("WSDcrdata failed to unsubscribe from %v: %v",
			event, err)
	}

	w.removeSub(event)
	log.Debugf("WSDcrdata successfully unsubscribed from %v", event)
	return nil
}

// Receive returns a channel that is listening for messages from dcrdata.
func (w *WSDcrdata) Receive() (<-chan *client.ClientMessage, error) {
	if w.IsShutdown() {
		return nil, ErrShutdown
	}

	return w.client.Receive(), nil
}

// ping pings the dcrdata server.
func (w *WSDcrdata) ping() error {
	if w.IsShutdown() {
		return ErrShutdown
	}

	return w.client.Ping()
}

// SubToAddr adds a subscription to a decred address
func (w *WSDcrdata) SubToAddr(address string) error {
	return w.Subscribe(AddrSubPrefix + address)
}

// UnsubFromAddr removes a subscription to a decred address.
func (w *WSDcrdata) UnsubFromAddr(address string) error {
	return w.unsubscribe(AddrSubPrefix + address)
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

// Reconnect creates a new websocket client, and subscribes to the
// same subscriptions as the previous client.
func (w *WSDcrdata) Reconnect() error {
	if w.IsShutdown() {
		return ErrShutdown
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
		if err == ErrShutdown {
			return ErrShutdown
		} else if err != nil {
			log.Errorf("WSDcrdata failed to ping dcrdata: %v", err)
			w.client.Stop()

			// Existing subscriptions have gone bad
			for sub := range w.subscriptions {
				prevSubscriptions[sub] = struct{}{}
			}
			w.removeAllSubs()

			// Reconnect
			c, err := newDcrdataWSClient(w.url)
			if err != nil {
				log.Errorf("WSDcrdata failed to create new client while "+
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
				log.Errorf("WSDcrdata failed to subscribe to %v: %v",
					sub, err)
				goto wait
			}
			w.addSub(sub)
			delete(prevSubscriptions, sub)
		}

	wait:
		if len(prevSubscriptions) > 0 {
			log.Debugf("WSDcrdata reconnect waiting %v", timeToWait)
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

// NewWSDcrdata return a new WSDcrdata context.
func NewWSDcrdata(dcrdataURL string) (*WSDcrdata, error) {
	client, err := newDcrdataWSClient(dcrdataURL)
	if err != nil {
		return nil, err
	}

	return &WSDcrdata{
		client:        client,
		subscriptions: make(map[string]struct{}),
		url:           dcrdataURL,
	}, nil
}
