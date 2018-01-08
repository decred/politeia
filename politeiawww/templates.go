// Copyright (c) 2017 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

const templateNewUserEmailRaw = `
<div>Click the link below to verify your email and complete your registration:</div>
<div style="margin: 20px 0 0 10px"><a href="{{.Link}}">{{.Link}}</a></div>
<div style="margin-top: 20px">You are receiving this email because
<span style="font-weight: bold">{{.Email}}</span> was used to register for Politeia.</div>
`

const templateResetPasswordEmailRaw = `
<div>Click the link below to continue resetting your password:</div>
<div style="margin: 20px 0 0 10px"><a href="{{.Link}}">{{.Link}}</a></div>
<div style="margin-top: 20px">You are receiving this email because a password reset
was initiated for <span style="font-weight: bold">{{.Email}}</span> on Politeia.</div>
`

const templateUpdateUserKeyEmailRaw = `
<div>Click the link below to continue setting a new key pair:</div>
<div style="margin: 20px 0 0 10px"><a href="{{.Link}}">{{.Link}}</a></div>
<div style="margin-top: 20px">You are receiving this email because a new key pair
(public key: {{.PublicKey}}) was generated for
<span style="font-weight: bold">{{.Email}}</span> on Politeia.</div>
`
