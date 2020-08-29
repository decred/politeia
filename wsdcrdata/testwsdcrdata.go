package wsdcrdata

import client "github.com/decred/dcrdata/pubsub/v4/psclient"

// TestWSDcrdata can be used to simulate a dcrdata websocket connection in
// tests.
type TestWSDcrdata struct {
	status   StatusT
	receiver chan *client.ClientMessage
}

// SendMessage allows TestWSDcrdata to send a dcrdata message to the client.
func (t *TestWSDcrdata) SendMessage(msg *client.ClientMessage) {
	t.receiver <- msg
}

// Status is a stub used to satisfy the Client interface.
func (t *TestWSDcrdata) Status() StatusT {
	return t.status
}

// Close is a stub used to satisfy the Client interface.
func (t *TestWSDcrdata) Close() error {
	t.status = StatusShutdown
	return nil
}

// Receive is a stub used to satisfy the Client interface.
func (t *TestWSDcrdata) Receive() <-chan *client.ClientMessage {
	return t.receiver
}

// AddressSubscribe is a stub used to satisfy the Client interface.
func (t *TestWSDcrdata) AddressSubscribe(string) error {
	return nil
}

// AddressUnsubscribe is a stub used to satisfy the Client interface.
func (t *TestWSDcrdata) AddressUnsubscribe(string) error {
	return nil
}

// NewBlockSubscribe is a stub used to satisfy the Client interface.
func (t *TestWSDcrdata) NewBlockSubscribe() error {
	return nil
}

// NewBlockUnsubscribe is a stub used to satisfy the Client interface.
func (t *TestWSDcrdata) NewBlockUnsubscribe() error {
	return nil
}

// Reconnect is a stub used to satisfy the Client interface.
func (t *TestWSDcrdata) Reconnect() {
}

// NewTest returns a new TestWSDcrdata struct
func NewTest() *TestWSDcrdata {
	return &TestWSDcrdata{
		receiver: make(chan *client.ClientMessage),
	}
}
