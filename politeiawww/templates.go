// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

const templateNewUserEmailRaw = `
<div>Click the link below to verify your email and complete your registration:</div>
<div style="margin: 20px 0 0 10px"><a href="{{.Link}}">{{.Link}}</a></div>
<div style="margin-top: 20px">You are receiving this email because
<span style="font-weight: bold">{{.Email}}</span> was used to register for Politeia.
If you did not perform this action, please ignore this email.</div>
`

const templateResetPasswordEmailRaw = `
<div>Click the link below to continue resetting your password:</div>
<div style="margin: 20px 0 0 10px"><a href="{{.Link}}">{{.Link}}</a></div>
<div style="margin-top: 20px">You are receiving this email because a password reset
was initiated for <span style="font-weight: bold">{{.Email}}</span> on Politeia.
If you did not perform this action, please contact Politeia administrators.</div>
`

const templateUpdateUserKeyEmailRaw = `
<div>Click the link below to verify your new identity:</div>
<div style="margin: 20px 0 0 10px"><a href="{{.Link}}">{{.Link}}</a></div>
<div style="margin-top: 20px">You are receiving this email because a new identity
(public key: {{.PublicKey}}) was generated for
<span style="font-weight: bold">{{.Email}}</span> on Politeia. If you did not perform
this action, please contact Politeia administrators.</div>
`

const templateUserLockedResetPasswordRaw = `
<div>Your account was locked due to too many login attempts. You need to reset your password in order to unlock your account:</div>
<div style="margin: 20px 0 0 10px"><a href="{{.Link}}">{{.Link}}</a></div>
<div style="margin-top: 20px">You are receiving this email because someone made too many login attempts for <span style="font-weight: bold">{{.Email}}</span> on Politeia.</div>
<div>If that was not you, please notify Politeia administrators.</div>
`

const templateNewProposalSubmittedRaw = `
<div>A new proposal has been submitted on Politeia by <b>{{.Username}} ({{.Email}})</b>:</div>
<div style="margin: 10px 0px;">
<a  href="{{.Link}}" style="font-size:20px; font-weight:bold">{{.Name}}</a><br>
</div>
`
