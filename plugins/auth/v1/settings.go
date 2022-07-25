// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

const (
	SettingHost = "host"

	// TODO session max age belongs in the server layer. The auth manager should
	// get it from the server on initialization.
	// SettingSessionMaxAge is the plugin setting name for the max session age.
	// The value is in seconds. Sessions expire once they exceed this age limit.
	SettingSessionMaxAge = "session_max_age"

	SettingsUsernameChars = "username_chars"

	SettingUsernameMinLength = "username_min_length"

	SettingUsernameMaxLength = "username_max_length"

	SettingPasswordMinLength = "password_min_length"

	SettingPasswordMaxLength = "password_max_length"

	SettingContactTypes = "contact_types"
)
