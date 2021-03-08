// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package records

import (
	v1 "github.com/decred/politeia/politeiawww/api/records/v1"
	"github.com/decred/politeia/politeiawww/user"
)

const (
	// EventTypeNew is emitted when a new record is submitted.
	EventTypeNew = "records-new"

	// EventTypeEdit is emitted when a a record is edited.
	EventTypeEdit = "records-edit"

	// EventTypeSetStatus is emitted when a a record status is updated.
	EventTypeSetStatus = "records-setstatus"
)

// EventNew is the event data for the EventTypeNew.
type EventNew struct {
	User   user.User
	Record v1.Record
}

// EventEdit is the event data for the EventTypeEdit.
type EventEdit struct {
	User   user.User
	Record v1.Record
}

// EventSetStatus is the event data for the EventTypeSetStatus.
type EventSetStatus struct {
	Record v1.Record
}
