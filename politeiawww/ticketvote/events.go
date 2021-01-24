// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package ticketvote

import (
	tkv1 "github.com/decred/politeia/politeiawww/api/ticketvote/v1"
	"github.com/decred/politeia/politeiawww/user"
)

const (
	// EventTypeAuthorize is emitted when a vote is authorized.
	EventTypeAuthorize = "ticketvote-authorize"

	// EventTypeStart is emitted when a vote is started.
	EventTypeStart = "ticketvote-start"
)

// EventAuthorize is the event data for EventTypeAuthorize.
type EventAuthorize struct {
	Auth tkv1.Authorize
	User user.User
}

// EventStart is the event data for EventTypeStart.
type EventStart struct {
	Start tkv1.Start
	User  user.User
}
