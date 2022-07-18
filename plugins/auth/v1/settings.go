// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

var (
	// SettingSessionMaxAge is the plugin setting name for the max session age.
	// The value is in seconds. Sessions expire once they exceed this age limit.
	SettingSessionMaxAge = "session_max_age"

	// SessionMaxAge is the default max session age. The value is in seconds.
	SessionMaxAge int64 = 60 * 60 * 24 // 1 day

	SettingsUsernameChars = "username_chars"
	UsernameChars         = []string{"A-z", "0-9", "_"}

	SettingUsernameMinLength        = "username_min_length"
	UsernameMinLength        uint32 = 3

	SettingUsernameMaxLength        = "username_max_length"
	UsernameMaxLength        uint32 = 15

	SettingPasswordMinLength        = "password_min_length"
	PasswordMinLength        uint32 = 8

	SettingPasswordMaxLength        = "password_max_length"
	PasswordMaxLength        uint32 = 128
)
