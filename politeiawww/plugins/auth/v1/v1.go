// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

const (
	PluginID             = "auth"
	PluginVersion uint32 = 1
)

type ErrorCode uint32

var (
	InvalidError ErrorCode = 0

	InvalidPluginID ErrorCode = 1

	InvalidPluginVersion ErrorCode = 2

	InvalidCommand ErrorCode = 3
)
