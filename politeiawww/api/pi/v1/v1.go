// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

const (
	// APIRoute is prefixed onto all routes defined in this package.
	APIRoute = "/pi/v1"

	// RoutePolicy returns the policy for the pi API.
	RoutePolicy = "/policy"
)

// Policy requests the policy settings for the pi API. It includes the policy
// guidlines for the contents of a proposal record.
type Policy struct{}

// PolicyReply is the reply to the Policy command.
type PolicyReply struct {
	TextFileSizeMax    uint32   `json:"textfilesizemax"` // In bytes
	ImageFileCountMax  uint32   `json:"imagefilecountmax"`
	ImageFileSizeMax   uint32   `json:"imagefilesizemax"` // In bytes
	NameLengthMin      uint32   `json:"namelengthmin"`    // In characters
	NameLengthMax      uint32   `json:"namelengthmax"`    // In characters
	NameSupportedChars []string `json:"namesupportedchars"`
}
