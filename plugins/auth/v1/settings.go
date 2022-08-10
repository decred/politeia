// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

const (
	SettingHost = "host"

	SettingsUsernameChars = "username_chars"

	SettingUsernameMinLength = "username_min_length"

	SettingUsernameMaxLength = "username_max_length"

	SettingPasswordMinLength = "password_min_length"

	SettingPasswordMaxLength = "password_max_length"

	// SettingMaxFailedLogins is the maximum number of logins that a user can
	// attempt over a 24 hour period due to the wrong password. Once the failed
	// login attempts has been exceeded, the user account is locked and must be
	// unlocked by an admin.
	SettingMaxFailedLogins = "max_failed_logins"

	SettingContactTypes = "contact_types"
)
