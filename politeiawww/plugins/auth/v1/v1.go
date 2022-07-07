// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package v1

const (
	PluginID             = "auth"
	PluginVersion uint32 = 1
)

const (
	CmdNewUser        = "newuser"
	CmdLogin          = "login"
	CmdLogout         = "logout"
	CmdVerifyEmail    = "verifyemail"
	CmdResendEmail    = "resendemail"
	CmdSetTOTP        = "settotp"
	CmdVerifyTOTP     = "verifytotp"
	CmdDisableTOTP    = "disabletotp"
	CmdUpdateUserPerm = "updateuserperm"
	CmdUpdatePassword = "updatepassword"
	CmdResetPassword  = "resetpassword"
	CmdUpdateEmail    = "updateemail"
	CmdDelEmail       = "delemail"
	CmdUpdateUsername = "updateusername"
)

const (
	PermPublic = "public"
	PermUser   = "user"
	PermAdmin  = "admin"
)
