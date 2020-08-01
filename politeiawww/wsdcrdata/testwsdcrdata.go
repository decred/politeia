package wsdcrdata

import client "github.com/decred/dcrdata/pubsub/v4/psclient"

// TestWSDcrdata can be used to simulate a dcrdata websocket connection in
// tests.
type TestWSDcrdata struct {
	isShutdown bool
	receiver   chan *client.ClientMessage
}

// SendMessage allows TestWSDcrdata to send a dcrdata message to the client.
func (t *TestWSDcrdata) SendMessage(msg *client.ClientMessage) {
	t.receiver <- msg
}

// IsShutdown is a stub used to satisfy the WSDcrdata interface.
func (t *TestWSDcrdata) IsShutdown() bool {
	return t.isShutdown
}

// Close is a stub used to satisfy the WSDcrdata interface.
func (t *TestWSDcrdata) Close() error {
	t.isShutdown = true
	return nil
}

// Subscribe is a stub used to satisfy the WSDcrdata interface.
func (t *TestWSDcrdata) Subscribe(string) error {
	return nil
}

// Unsubscribe is a stub used to satisfy the WSDcrdata interface.
func (t *TestWSDcrdata) Unsubscribe(string) error {
	return nil
}

// Receive is a stub used to satisfy the WSDcrdata interface.
func (t *TestWSDcrdata) Receive() (<-chan *client.ClientMessage, error) {
	return t.receiver, nil
}

// SubToAddr is a stub used to satisfy the WSDcrdata interface.
func (t *TestWSDcrdata) SubToAddr(string) error {
	return nil
}

// UnsubFromAddr is a stub used to satisfy the WSDcrdata interface.
func (t *TestWSDcrdata) UnsubFromAddr(string) error {
	return nil
}

// Reconnect is a stub used to satisfy the WSDcrdata interface.
func (t *TestWSDcrdata) Reconnect() error {
	return nil
}

// NewTestWSDcrdata returns a new TestWSDcrdata struct
func NewTestWSDcrdata() *TestWSDcrdata {
	return &TestWSDcrdata{
		receiver: make(chan *client.ClientMessage),
	}
}
