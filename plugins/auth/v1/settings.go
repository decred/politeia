// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

const (
	// SettingSessionMaxAge is the plugin setting name for the max session age.
	// The value is in seconds. Sessions expire once they exceed this age limit.
	SettingSessionMaxAge = "session_max_age"

	// SessionMaxAge is the default max session age. The value is in seconds.
	SessionMaxAge int64 = 60 * 60 * 24 // 1 day
)
