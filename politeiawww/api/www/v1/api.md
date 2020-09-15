# politeiawww API Specification

# v1

This document describes the REST API provided by a `politeiawww` server.  The
`politeiawww` server is the web server backend and it interacts with a JSON
REST API.  This document also describes websockets for server side
notifications.  It does not render HTML.

**Methods**

- [`Version`](#version)
- [`Policy`](#policy)
- [`New user`](#new-user)
- [`Verify user`](#verify-user)
- [`Resend verification`](#resend-verification)
- [`Me`](#me)
- [`Login`](#login)
- [`Logout`](#logout)
- [`User details`](#user-details)
- [`Edit user`](#edit-user)
- [`Users`](#users)
- [`Update user key`](#update-user-key)
- [`Verify update user key`](#verify-update-user-key)
- [`Change username`](#change-username)
- [`Change password`](#change-password)
- [`Reset password`](#reset-password)
- [`User proposal credits`](#user-proposal-credits)
- [`User comments votes`](#user-comments-votes)

**Proposal Routes**
- [`Vetted`](#vetted)
- [`User proposals`](#user-proposals)
- [`Proposal paywall details`](#proposal-paywall-details)
- [`Verify user payment`](#verify-user-payment)
- [`New proposal`](#new-proposal)
- [`Edit Proposal`](#edit-proposal)
- [`Proposal details`](#proposal-details)
- [`Batch proposals`](#batch-proposals)
- [`Batch vote summary`](#batch-vote-summary)
- [`Set proposal status`](#set-proposal-status)
- [`Authorize vote`](#authorize-vote)
- [`Active votes`](#active-votes)
- [`Cast votes`](#cast-votes)
- [`Proposal vote status`](#proposal-vote-status)
- [`Proposals vote status`](#proposals-vote-status)
- [`Vote results`](#vote-results)
- [`Token inventory`](#token-inventory)
- [`New comment`](#new-comment)
- [`Get comments`](#get-comments)
- [`Like comment`](#like-comment)
- [`Censor comment`](#censor-comment)


**Error status codes**

- [`ErrorStatusInvalid`](#ErrorStatusInvalid)
- [`ErrorStatusInvalidPassword`](#ErrorStatusInvalidPassword)
- [`ErrorStatusMalformedEmail`](#ErrorStatusMalformedEmail)
- [`ErrorStatusVerificationTokenInvalid`](#ErrorStatusVerificationTokenInvalid)
- [`ErrorStatusVerificationTokenExpired`](#ErrorStatusVerificationTokenExpired)
- [`ErrorStatusProposalMissingFiles`](#ErrorStatusProposalMissingFiles)
- [`ErrorStatusProposalNotFound`](#ErrorStatusProposalNotFound)
- [`ErrorStatusProposalDuplicateFilenames`](#ErrorStatusProposalDuplicateFilenames)
- [`ErrorStatusProposalInvalidTitle`](#ErrorStatusProposalInvalidTitle)
- [`ErrorStatusMaxMDsExceededPolicy`](#ErrorStatusMaxMDsExceededPolicy)
- [`ErrorStatusMaxImagesExceededPolicy`](#ErrorStatusMaxImagesExceededPolicy)
- [`ErrorStatusMaxMDSizeExceededPolicy`](#ErrorStatusMaxMDSizeExceededPolicy)
- [`ErrorStatusMaxImageSizeExceededPolicy`](#ErrorStatusMaxImageSizeExceededPolicy)
- [`ErrorStatusMalformedPassword`](#ErrorStatusMalformedPassword)
- [`ErrorStatusCommentNotFound`](#ErrorStatusCommentNotFound)
- [`ErrorStatusInvalidFilename`](#ErrorStatusInvalidFilename)
- [`ErrorStatusInvalidFileDigest`](#ErrorStatusInvalidFileDigest)
- [`ErrorStatusInvalidBase64`](#ErrorStatusInvalidBase64)
- [`ErrorStatusInvalidMIMEType`](#ErrorStatusInvalidMIMEType)
- [`ErrorStatusUnsupportedMIMEType`](#ErrorStatusUnsupportedMIMEType)
- [`ErrorStatusInvalidPropStatusTransition`](#ErrorStatusInvalidPropStatusTransition)
- [`ErrorStatusInvalidPublicKey`](#ErrorStatusInvalidPublicKey)
- [`ErrorStatusNoPublicKey`](#ErrorStatusNoPublicKey)
- [`ErrorStatusInvalidSignature`](#ErrorStatusInvalidSignature)
- [`ErrorStatusInvalidInput`](#ErrorStatusInvalidInput)
- [`ErrorStatusInvalidSigningKey`](#ErrorStatusInvalidSigningKey)
- [`ErrorStatusCommentLengthExceededPolicy`](#ErrorStatusCommentLengthExceededPolicy)
- [`ErrorStatusUserNotFound`](#ErrorStatusUserNotFound)
- [`ErrorStatusWrongStatus`](#ErrorStatusWrongStatus)
- [`ErrorStatusNotLoggedIn`](#ErrorStatusNotLoggedIn)
- [`ErrorStatusUserNotPaid`](#ErrorStatusUserNotPaid)
- [`ErrorStatusReviewerAdminEqualsAuthor`](#ErrorStatusReviewerAdminEqualsAuthor)
- [`ErrorStatusMalformedUsername`](#ErrorStatusMalformedUsername)
- [`ErrorStatusDuplicateUsername`](#ErrorStatusDuplicateUsername)
- [`ErrorStatusVerificationTokenUnexpired`](#ErrorStatusVerificationTokenUnexpired)
- [`ErrorStatusCannotVerifyPayment`](#ErrorStatusCannotVerifyPayment)
- [`ErrorStatusDuplicatePublicKey`](#ErrorStatusDuplicatePublicKey)
- [`ErrorStatusInvalidPropVoteStatus`](#ErrorStatusInvalidPropVoteStatus)
- [`ErrorStatusNoProposalCredits`](#ErrorStatusNoProposalCredits)
- [`ErrorStatusInvalidUserManageAction`](#ErrorStatusInvalidUserManageAction)
- [`ErrorStatusUserActionNotAllowed`](#ErrorStatusUserActionNotAllowed)
- [`ErrorStatusWrongVoteStatus`](#ErrorStatusWrongVoteStatus)
- [`ErrorStatusCannotVoteOnPropComment`](#ErrorStatusCannotVoteOnPropComment)
- [`ErrorStatusChangeMessageCannotBeBlank`](#ErrorStatusChangeMessageCannotBeBlank)
- [`ErrorStatusCensorReasonCannotBeBlank`](#ErrorStatusCensorReasonCannotBeBlank)
- [`ErrorStatusCannotCensorComment`](#ErrorStatusCannotCensorComment)
- [`ErrorStatusUserNotAuthor`](#ErrorStatusUserNotAuthor)
- [`ErrorStatusVoteNotAuthorized`](#ErrorStatusVoteNotAuthorized)
- [`ErrorStatusVoteAlreadyAuthorized`](#ErrorStatusVoteAlreadyAuthorized)
- [`ErrorStatusInvalidAuthVoteAction`](#ErrorStatusInvalidAuthVoteAction)
- [`ErrorStatusUserDeactivated`](#ErrorStatusUserDeactivated)
- [`ErrorStatusInvalidPropVoteBits`](#ErrorStatusInvalidPropVoteBits)
- [`ErrorStatusInvalidPropVoteParams`](#ErrorStatusInvalidPropVoteParams)
- [`ErrorStatusEmailNotVerified`](#ErrorStatusEmailNotVerified)
- [`ErrorStatusInvalidUUID`](#ErrorStatusInvalidUUID)
- [`ErrorStatusInvalidLikeCommentAction`](#ErrorStatusInvalidLikeCommentAction)
- [`ErrorStatusInvalidCensorshipToken`](#ErrorStatusInvalidCensorshipToken)
- [`ErrorStatusEmailAlreadyVerified`](#ErrorStatusEmailAlreadyVerified)
- [`ErrorStatusNoProposalChanges`](#ErrorStatusNoProposalChanges)
- [`ErrorStatusMaxProposalsExceededPolicy`](#ErrorStatusMaxProposalsExceededPolicy)
- [`ErrorStatusDuplicateComment`](#ErrorStatusDuplicateComment)
- [`ErrorStatusInvalidLogin`](#ErrorStatusInvalidLogin)
- [`ErrorStatusCommentIsCensored`](#ErrorStatusCommentIsCensored)
- [`ErrorStatusInvalidProposalVersion`](#ErrorStatusInvalidProposalVersion)
- [`ErrorStatusMetadataInvalid`](#ErrorStatusMetadataInvalid)
- [`ErrorStatusMetadataMissing`](#ErrorStatusMetadataMissing)
- [`ErrorStatusMetadataDigestInvalid`](#ErrorStatusMetadataDigestInvalid)
- [`ErrorStatusInvalidVoteType`](#ErrorStatusInvalidVoteType)
- [`ErrorStatusInvalidVoteOptions`](#ErrorStatusInvalidVoteOptions)
- [`ErrorStatusLinkByDeadlineNotMet`](#ErrorStatusLinkByDeadlineNotMet)
- [`ErrorStatusNoLinkedProposals`](#ErrorStatusNoLinkedProposals)
- [`ErrorStatusInvalidLinkTo`](#ErrorStatusInvalidLinkTo)
- [`ErrorStatusInvalidLinkBy`](#ErrorStatusInvalidLinkBy)
- [`ErrorStatusInvalidRunoffVote`](#ErrorStatusInvalidRunoffVote)
- [`ErrorStatusWrongProposalType`](#ErrorStatusWrongProposalType)

**Websockets**

See [`Websocket command flow`](#Websocket-command-flow) for a generic
description of websocket command flow.

- [`WSError`](#WSError)
- [`WSHeader`](#WSHeader)
- [`WSPing`](#WSPing)
- [`WSSubscribe`](#WSSubscribe)

## HTTP status codes and errors

All methods, unless otherwise specified, shall return `200 OK` when successful,
`400 Bad Request` when an error has occurred due to user input, or `500
Internal Server Error` when an unexpected server error has occurred. The format
of errors is as follows:

**`4xx` errors**

| | Type | Description |
|-|-|-|
| errorcode | number | One of the [error codes](#error-codes) |
| errorcontext | Array of Strings | This array of strings is used to provide additional information for certain errors; see the documentation for specific error codes. |

**`5xx` errors**

| | Type | Description |
|-|-|-|
| errorcode | number | An error code that can be used to track down the internal server error that occurred; it should be reported to Politeia administrators. |

## Websocket command flow

There are two distinct websockets routes. There is an unauthenticated route and
an authenticated route.  The authenticated route provides access to all
unprivileged websocket commands and therefore a client that authenticates
itself via the [`Login`](#login) call should close any open unprivileged
websockets.  Note that sending notifications to unauthenticated users means
**ALL** unauthenticated users; this may be expensive and should be used
carefully.

All commands consist of two JSON structures. All commands are prefixed by a
[`WSHeader`](#WSHeader) structure that identifies the command that follows.
This is done to prevent decoding JSON multiple times.  That structure also
contains a convenience field called **ID** which can be set by the client in
order to identify prior sent commands.

If a client command fails the server shall return a [`WSError`](#WSError)
structure, prefixed by a [`WSHeader`](#WSHeader) structure that contains the
client side **ID** followed by the error(s) itself.  If there is no failure the
server does not reply.  Note that **ID** is unused when server notifications
flow to the client.

Both routes operate exactly the same way. The only difference is denied access
to subscriptions of privileged notifications.

**Unauthenticated route**: `/v1/ws`
**Authenticated route**: `/v1/aws`

For example, a subscribe command consists of a [`WSHeader`](#WSHeader)
structure followed by a [`WSSubscribe`](#WSSubscribe) structure:
```
{
  "command": "subscribe",
  "id": "1"
}
{
  "rpcs": [
    "ping"
  ]
}
```

The same example but with an invalid subscription:
```
{
  "command": "subscribe",
  "id": "1"
}
{
  "rpcs": [
    "pingo"
  ]
}
```

Since **pingo** is an invalid subscription the server will reply with the
following error:
```
{
  "command": "error",
  "id": "1"
}
{
  "command": "subscribe",
  "id": "1",
  "errors": [
    "invalid subscription pingo"
  ]
}
```

## Methods

### `Version`

Obtain version, route information and signing identity from server.  This call
shall **ALWAYS** be the first contact with the server.  This is done in order
to get the CSRF token for the session and to ensure API compatibility.

**Route**: `GET /` and `GET /version`

**Params**: none

**Results**:

| | Type | Description |
|-|-|-|
| version | number | API version that is running on this server. |
| route | string | Route that should be prepended to all calls. For example, "/v1". |
| pubkey | string | The public key for the corresponding private key that signs various tokens to ensure server authenticity and to prevent replay attacks. |
| testnet | boolean | Value to inform either its running on testnet or not |
| mode | string | Current mode that politeiawww is running (possibly piwww or cmswww) |
| activeusersesstion | boolean | Indicates if there is an active user from the session or not |

**Example**

Request:

```json
{}
```

Reply:

```json
{
  "version": 1,
  "route": "/v1",
  "pubkey": "99e748e13d7ecf70ef6b5afa376d692cd7cb4dbb3d26fa83f417d29e44c6bb6c",
  "testnet": true,
  "mode": "piwww",
  "activeusersession": true
}
```

### `Me`

Return pertinent user information of the current logged in user.

**Route**: `GET /v1/user/me`

**Params**: none

**Results**: See the [`Login reply`](#login-reply).

**Example**

Request:

```json
{}
```

Reply:

```json
{
  "isadmin":false,
  "userid":"12",
  "email":"69af376cca42cd9c@example.com",
  "publickey":"5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b",
  "paywalladdress":"Tsgs7qb1Gnc43D9EY3xx9ou8Lbo8rB7me6M",
  "paywallamount": 10000000,
  "paywalltxnotbefore": 1528821554
}
```

### `New user`

Create a new user on the politeiawww server.

**Route:** `POST /v1/user/new`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| email | string | Email is used as the web site user identity for a user. When a user changes email addresses the server shall maintain a mapping between the old and new address. | Yes |
| username | string | Unique username that the user wishes to use. | Yes |
| password | string | The password that the user wishes to use. This password travels in the clear in order to enable JS-less systems. The server shall never store passwords in the clear. | Yes |
| publickey | string | User ed25519 public key. | Yes |

**Results:**

| Parameter | Type | Description |
|-|-|-|
| verificationtoken | String | The verification token which is required when calling [`Verify user`](#verify-user). If an email server is set up, this property will be empty or nonexistent; the token will be sent to the email address sent in the request.|

This call can return one of the following error codes:

- [`ErrorStatusMalformedEmail`](#ErrorStatusMalformedEmail)
- [`ErrorStatusMalformedUsername`](#ErrorStatusMalformedUsername)
- [`ErrorStatusDuplicateUsername`](#ErrorStatusDuplicateUsername)
- [`ErrorStatusMalformedPassword`](#ErrorStatusMalformedPassword)
- [`ErrorStatusInvalidPublicKey`](#ErrorStatusInvalidPublicKey)
- [`ErrorStatusDuplicatePublicKey`](#ErrorStatusDuplicatePublicKey)

The email shall include a link in the following format:

```
/user/verify?email=69af376cca42cd9c@example.com&verificationtoken=fc8f660e7f4d590e27e6b11639ceeaaec2ce9bc6b0303344555ac023ab8ee55f
```

The call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

* **Example**

Request:

```json
{
  "email": "69af376cca42cd9c@example.com",
  "password": "69af376cca42cd9c",
  "username": "foobar",
  "publickey":"5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b"
}
```

Reply:

```json
{
  "verificationtoken": "fc8f660e7f4d590e27e6b11639ceeaaec2ce9bc6b0303344555ac023ab8ee55f"
}
```

### `Verify user`

Verify email address of a previously created user.

**Route:** `GET /v1/user/verify`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| email | string | Email address of previously created user. | Yes |
| verificationtoken | string | The token that was provided by email to the user. | Yes |
| signature | string | The ed25519 signature of the string representation of the verification token. | Yes |

**Results:** none

On success the call shall return `200 OK`.

On failure the call shall return `400 Bad Request` and one of the following error codes:
- [`ErrorStatusVerificationTokenInvalid`](#ErrorStatusVerificationTokenInvalid)
- [`ErrorStatusVerificationTokenExpired`](#ErrorStatusVerificationTokenExpired)
- [`ErrorStatusNoPublicKey`](#ErrorStatusNoPublicKey)
- [`ErrorStatusInvalidPublicKey`](#ErrorStatusInvalidPublicKey)
- [`ErrorStatusInvalidSignature`](#ErrorStatusInvalidSignature)
- [`ErrorStatusInvalidInput`](#ErrorStatusInvalidInput)

**Example:**

Request:

The request params should be provided within the URL:

```
/v1/user/verify?email=abc@example.com&verificationtoken=f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde&signature=9e4b1018913610c12496ec3e482f2fb42129197001c5d35d4f5848b77d2b5e5071f79b18bcab4f371c5b378280bb478c153b696003ac3a627c3d8a088cd5f00d
```

Reply:

```json
{}
```

### `Resend verification`

Sends another verification email for a new user registration.

**Route:** `POST /v1/user/new/resend`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| email | string | Email address which was used to sign up. | Yes |
| publickey | string | User ed25519 public key. This can be the same key used to sign up or a new one. | Yes |

**Results:**

| Parameter | Type | Description |
|-|-|-|
| verificationtoken | String | The verification token which is required when calling [`Verify user`](#verify-user). If an email server is set up, this property will be empty or nonexistent; the token will be sent to the email address sent in the request.|

This call can return one of the following error codes:

- [`ErrorStatusInvalidPublicKey`](#ErrorStatusInvalidPublicKey)
- [`ErrorStatusDuplicatePublicKey`](#ErrorStatusDuplicatePublicKey)

The email shall include a link in the following format:

```
/user/verify?email=69af376cca42cd9c@example.com&verificationtoken=fc8f660e7f4d590e27e6b11639ceeaaec2ce9bc6b0303344555ac023ab8ee55f
```

The call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

* **Example**

Request:

```json
{
  "email": "69af376cca42cd9c@example.com",
  "publickey":"5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b"
}
```

Reply:

```json
{
  "verificationtoken": "fc8f660e7f4d590e27e6b11639ceeaaec2ce9bc6b0303344555ac023ab8ee55f"
}
```

### `Login`

Login as a user or admin.  Admin status is determined by the server based on
the user database.  Note that Login reply is identical to Me reply.

**Route:** `POST /v1/login`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| email | string | Email address of user that is attempting to login. | Yes |
| password | string | Accompanying password for provided email. | Yes |

**Results:** See the [`Login reply`](#login-reply).

On failure the call shall return `401 Unauthorized` and one of the following
error codes:
- [`ErrorStatusInvalidLogin`](#ErrorStatusInvalidLogin)
- [`ErrorStatusEmailNotVerified`](#ErrorStatusEmailNotVerified)
- [`ErrorStatusUserDeactivated`](#ErrorStatusUserDeactivated)
- [`ErrorStatusUserLocked`](#ErrorStatusUserLocked)

**Example**

Request:

```json
{
  "email":"26c5687daca2f5d8@example.com",
  "password":"26c5687daca2f5d8"
}
```

Reply:

```json
{
  "isadmin":true,
  "userid":"0",
  "email":"26c5687daca2f5d8@example.com",
  "publickey":"ec88b934fd9f334a9ed6d2e719da2bdb2061de5370ff20a38b0e1e3c9538199a",
  "paywalladdress":"",
  "paywallamount":"",
  "paywalltxnotbefore":""
}
```

### `Logout`

Logout as a user or admin.

**Route:** `POST /v1/logout`

**Params:** none

**Results:** none

**Example**

Request:

```json
{}
```

Reply:

```json
{}
```

### `Verify user payment`

Checks that a user has paid his user registration fee.

**Route:** `GET /v1/user/verifypayment`

**Params:** none

**Results:**

| Parameter | Type | Description |
|-|-|-|
| haspaid | boolean | Whether or not a transaction on the blockchain that was sent to the `paywalladdress` |
| paywalladdress | String | The address in which to send the transaction containing the `paywallamount`.  If the user has already paid, this field will be empty or not present. |
| paywallamount | Int64 | The amount of DCR (in atoms) to send to `paywalladdress`.  If the user has already paid, this field will be empty or not present. |
| paywalltxnotbefore | Int64 | The minimum UNIX time (in seconds) required for the block containing the transaction sent to `paywalladdress`.  If the user has already paid, this field will be empty or not present. |

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusCannotVerifyPayment`](#ErrorStatusCannotVerifyPayment)

**Example**

Request:

```
/v1/user/verifypayment
```

Reply:

```json
{
  "haspaid": true,
  "paywalladdress":"",
  "paywallamount":"",
  "paywalltxnotbefore":""
}
```

### `User details`

Returns details about a user given its id. Returns complete data if request is from
admin or own user, and omits private data if request is from a normal user or logged
out user.

**Route:** `GET /v1/user/{userid}`

**Params:**

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| userid | string | The unique id of the user. | Yes |

**Results:**

| Parameter | Type | Description |
|-|-|-|
| user | [User](#user) | The user details. |

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusUserNotFound`](#ErrorStatusUserNotFound)

**Example**

Request:

```json
{
  "userid": "0"
}
```

Reply:

For a logged in admin user or own user requesting data.

```json
{
  "user": {
    "id": "0",
    "email": "6b87b6ebb0c80cb7@example.com",
    "username": "6b87b6ebb0c80cb7",
    "isadmin": false,
    "newuserpaywalladdress": "Tsgs7qb1Gnc43D9EY3xx9ou8Lbo8rB7me6M",
    "newuserpaywallamount": 10000000,
    "newuserpaywalltx": "",
    "newuserpaywalltxnotbefore": 1528821554,
    "newuserpaywallpollexpiry": 1528821554,
    "newuserverificationtoken":
      "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
    "newuserverificationexpiry": 1528821554,
    "updatekeyverificationtoken":
      "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
    "updatekeyverificationexpiry": 1528821554,
    "resetpasswordverificationtoken":
      "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
    "resetpasswordverificationexpiry": 1528821554,
    "lastlogintime": 1571316271,
    "failedloginattemps": 3,
    "isdeactivated": false,
    "islocked": false,
    "identities": [{
      "pubkey":
        "5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b",
      "isactive": true
    }],
    "proposalCredits": 10,
    "emailnotifications": 3
  }
}
```

Reply:

For a unlogged or normal user requesting data.

```json
{
  "user": {
    "id": "0",
    "email": "",
    "username": "6b87b6ebb0c80cb7",
    "isadmin": false,
    "newuserpaywalladdress": "",
    "newuserpaywallamount": 0,
    "newuserpaywalltx": "",
    "newuserpaywalltxnotbefore": 0,
    "newuserpaywallpollexpiry": 0,
    "newuserverificationtoken": "",
    "newuserverificationexpiry": 0,
    "updatekeyverificationtoken": null,
    "updatekeyverificationexpiry": 0,
    "resetpasswordverificationtoken": null,
    "resetpasswordverificationexpiry": 0,
    "lastlogintime": 0,
    "failedloginattemps": 0,
    "isdeactivated": false,
    "islocked": false,
    "identities": [{
      "pubkey":
        "5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b",
      "isactive": true
    }],
    "proposalCredits": 0,
    "emailnotifications": 0
  }
}
```

### `Edit user`

Edits a user's details. This call requires admin privileges.

**Route:** `POST /v1/user/manage`

**Params:**

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| userid | string | The unique id of the user. | Yes |
| action | int64 | The [user edit action](#user-edit-actions) to execute on the user. | Yes |
| reason | string | The admin's reason for executing this action. | Yes |

**Results:** none

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusUserNotFound`](#ErrorStatusUserNotFound)
- [`ErrorStatusInvalidInput`](#ErrorStatusInvalidInput)
- [`ErrorStatusInvalidUserManageAction`](#ErrorStatusInvalidUserManageAction)

**Example**

Request:

```json
{
  "userid": "0",
  "action": 1
}
```

Reply:

```json
{}
```

### `Users`

Returns a list of users given optional filters. This call requires admin privileges.

**Route:** `GET /v1/users`

**Params:**

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| email | string | A query string to match against user email addresses. | |
| username | string | A query string to match against usernames. | |

**Results:**

| Parameter | Type | Description |
|-|-|-|
| totalusers | uint64 | The total number of all users in the database. |
| totalmatches | uint64 | The total number of users that matched the query. |
| users | array of [Abridged User](#abridged-user) | The list of users that match the query. This list will be capped at the `userlistpagesize`, which is specified in the [`Policy`](#policy) call. |

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusInvalidInput`](#ErrorStatusInvalidInput)

**Example**

Request:

```json
{
  "email": "@aol.com",
  "username": "JakeFromStateFarm"
}
```

Reply:

```json
{
  "totalusers": 132,
  "totalmatches": 0,
  "users": []
}
```

### `Update user key`

Updates the user's active key pair.

**Route:** `POST /v1/user/key`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| publickey | string | User's new active ed25519 public key. | Yes |

**Results:**

| Parameter | Type | Description |
|-|-|-|
| verificationtoken | String | The verification token which is required when calling [`Verify update user key`](#verify-update-user-key). If an email server is set up, this property will be empty or nonexistent; the token will be sent to the email address sent in the request. |

This call can return one of the following error codes:

- [`ErrorStatusInvalidPublicKey`](#ErrorStatusInvalidPublicKey)
- [`ErrorStatusVerificationTokenUnexpired`](#ErrorStatusVerificationTokenUnexpired)

The email shall include a link in the following format:

```
/v1/user/key/verify?verificationtoken=fc8f660e7f4d590e27e6b11639ceeaaec2ce9bc6b0303344555ac023ab8ee55
```

The call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

* **Example**

Request:

```json
{
  "publickey":"5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b"
}
```

Reply:

```json
{
  "verificationtoken": "fc8f660e7f4d590e27e6b11639ceeaaec2ce9bc6b0303344555ac023ab8ee55f"
}
```

### `Verify update user key`

Verify the new key pair for the user.

**Route:** `POST /v1/user/key/verify`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| verificationtoken | string | The token that was provided by email to the user. | Yes |
| signature | string | The ed25519 signature of the string representation of the verification token. | Yes |

**Results:** none

On success the call shall return `200 OK`.

On failure the call shall return `400 Bad Request` and one of the following error codes:
- [`ErrorStatusVerificationTokenInvalid`](#ErrorStatusVerificationTokenInvalid)
- [`ErrorStatusVerificationTokenExpired`](#ErrorStatusVerificationTokenExpired)
- [`ErrorStatusNoPublicKey`](#ErrorStatusNoPublicKey)
- [`ErrorStatusInvalidPublicKey`](#ErrorStatusInvalidPublicKey)
- [`ErrorStatusInvalidSignature`](#ErrorStatusInvalidSignature)
- [`ErrorStatusInvalidInput`](#ErrorStatusInvalidInput)

**Example:**

Request:

The request params should be provided within the URL:

```json
{
  "verificationtoken":"f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde",
  "signature":"9e4b1018913610c12496ec3e482f2fb42129197001c5d35d4f5848b77d2b5e5071f79b18bcab4f371c5b378280bb478c153b696003ac3a627c3d8a088cd5f00d"
}
```

Reply:

```json
{}
```

### `Change username`

Changes the username for the currently logged in user.

**Route:** `POST /v1/user/username/change`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| password | string | The current password of the logged in user. | Yes |
| newusername | string | The new username for the logged in user. | Yes |

**Results:** none

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusInvalidPassword`](#ErrorStatusInvalidPassword)
- [`ErrorStatusMalformedUsername`](#ErrorStatusMalformedUsername)
- [`ErrorStatusDuplicateUsername`](#ErrorStatusDuplicateUsername)

**Example**

Request:

```json
{
  "password": "15a1eb6de3681fec",
  "newusername": "foobar"
}
```

Reply:

```json
{}
```

### `Change password`

Changes the password for the currently logged in user.

**Route:** `POST /v1/user/password/change`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| currentpassword | string | The current password of the logged in user. | Yes |
| newpassword | string | The new password for the logged in user. | Yes |

**Results:** none

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusInvalidPassword`](#ErrorStatusInvalidPassword)
- [`ErrorStatusMalformedPassword`](#ErrorStatusMalformedPassword)

**Example**

Request:

```json
{
  "currentpassword": "15a1eb6de3681fec",
  "newpassword": "cef1863ed6be1a51"
}
```

Reply:

```json
{}
```

### `Reset password`

Allows a user to reset his password without being logged in.

**Route:** `POST /v1/user/password/reset`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| email | string | The email of the user whose password should be reset. | Yes |
| verificationtoken | string | The verification token which is sent to the user's email address. | Yes |
| newpassword | String | The new password for the user. | Yes |

**Results:**

| Parameter | Type | Description |
|-|-|-|
| verificationtoken | String | This command is special because it has to be called twice, the 2nd time the caller needs to supply the `verificationtoken` |


The reset password command is special.  It must be called **twice** with different
parameters.

For the 1st call, it should be called with only an `email` parameter. On success
it shall send an email to the address provided by `email` and return `200 OK`.

The email shall include a link in the following format:

```
/v1/user/password/reset?email=abc@example.com&verificationtoken=f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde
```

On failure, the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusMalformedEmail`](#ErrorStatusMalformedEmail)

For the 2nd call, it should be called with `email`, `token`, and `newpassword`
parameters.

On failure, the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusVerificationTokenInvalid`](#ErrorStatusVerificationTokenInvalid)
- [`ErrorStatusVerificationTokenExpired`](#ErrorStatusVerificationTokenExpired)
- [`ErrorStatusMalformedPassword`](#ErrorStatusMalformedPassword)

**Example for the 1st call**

Request:

```json
{
  "email": "6b87b6ebb0c80cb7@example.com"
}
```

Reply:

```json
{}
```

**Example for the 2nd call**

Request:

```json
{
  "email": "6b87b6ebb0c80cb7@example.com",
  "verificationtoken": "f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde",
  "newpassword": "6b87b6ebb0c80cb7"
}
```

Reply:

```json
{
  "verificationtoken": "f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde"
}
```

### `Proposal paywall details`
Retrieve paywall details that can be used to purchase proposal credits.
Proposal paywalls are only valid for one tx.  The user can purchase as many
proposal credits as they would like with that one tx. Proposal paywalls expire
after a set duration.  To verify that a payment has been made,
politeiawww polls the paywall address until the paywall is either paid or it
expires. A proposal paywall cannot be generated until the user has paid their
user registration fee.

**Route:** `GET /v1/proposals/paywall`

**Params:** none

**Results:**

| Parameter | Type | Description |
|-|-|-|
| creditprice | uint64 | Price per proposal credit in atoms. |
| paywalladdress | string | Proposal paywall address. |
| paywalltxnotbefore | string | Minimum timestamp for paywall tx. |
On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusUserNotPaid`](#ErrorStatusUserNotPaid)

**Example**

Request:

```json
{}
```

Reply:

```json
{
  "creditprice": 10000000,
  "paywalladdress": "TsRBnD2mnZX1upPMFNoQ1ckYr9Y4TZyuGTV",
  "paywalltxnotbefore": 1532445975
}
```

### `User proposal credits`
Request a list of the user's unspent and spent proposal credits.

**Route:** `GET /v1/user/proposals/credits`

**Params:** none

**Results:**

| Parameter | Type | Description |
|-|-|-|
| unspentcredits | array of [`ProposalCredit`](#proposal-credit)'s | The user's unspent proposal credits |
| spentcredits | array of [`ProposalCredit`](#proposal-credit)'s | The user's spent proposal credits |

**Example**

Request:

```json
{}
```

Reply:

```json
{
  "unspentcredits": [{
    "paywallid": 2,
    "price": 10000000,
    "datepurchased": 1532438228,
    "txid": "ff0207a03b761cb409c7677c5b5521562302653d2236c92d016dd47e0ae37bf7"
  }],
  "spentcredits": [{
    "paywallid": 1,
    "price": 10000000,
    "datepurchased": 1532437363,
    "txid": "1b6df077a0a745314dab58887c56c4261270bb7a809692fad8157a99a0c46477"
  }]
}
```

### `New proposal`

Submit a new proposal to the politeiawww server.

The Metadata field is required to include a [`Metadata`](#metadata) object that
contains an encoded [`ProposalMetadata`](#proposal-metadata).

**Route:** `POST /v1/proposals/new`

**Params:**

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| files | array of [`File`](#file)s | Files are the body of the proposal. It should consist of one markdown file - named "index.md" - and up to five pictures. **Note:** all parameters within each [`File`](#file) are required. | Yes |
| metadata | array of [`Metadata`](#metadata) | User specified proposal metadata.  |
| signature | string | Signature of the string representation of the Merkle root of the file payloads and the metadata payloads. Note that the merkle digests are calculated on the decoded payload.. | Yes |
| publickey | string | Public key from the client side, sent to politeiawww for verification | Yes |

**Results:**

| Parameter | Type | Description |
|-|-|-|
| censorshiprecord | [CensorshipRecord](#censorship-record) | A censorship record that provides the submitter with a method to extract the proposal and prove that he/she submitted it. |

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusNoProposalCredits`](#ErrorStatusNoProposalCredits)
- [`ErrorStatusProposalMissingFiles`](#ErrorStatusProposalMissingFiles)
- [`ErrorStatusProposalDuplicateFilenames`](#ErrorStatusProposalDuplicateFilenames)
- [`ErrorStatusProposalInvalidTitle`](#ErrorStatusProposalInvalidTitle)
- [`ErrorStatusMaxMDsExceededPolicy`](#ErrorStatusMaxMDsExceededPolicy)
- [`ErrorStatusMaxImagesExceededPolicy`](#ErrorStatusMaxImagesExceededPolicy)
- [`ErrorStatusMaxMDSizeExceededPolicy`](#ErrorStatusMaxMDSizeExceededPolicy)
- [`ErrorStatusMaxImageSizeExceededPolicy`](#ErrorStatusMaxImageSizeExceededPolicy)
- [`ErrorStatusInvalidSignature`](#ErrorStatusInvalidSignature)
- [`ErrorStatusInvalidSigningKey`](#ErrorStatusInvalidSigningKey)
- [`ErrorStatusUserNotPaid`](#ErrorStatusUserNotPaid)

**Example**

Request:

```json
{
  "name": "test",
  "files": [{
      "name":"index.md",
      "mime": "text/plain; charset=utf-8",
      "digest": "",
      "payload": "VGhpcyBpcyBhIGRlc2NyaXB0aW9u"
    }
  ]
}
```

Reply:

```json
{
  "censorshiprecord": {
    "token": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
    "merkle": "0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
    "signature": "fcc92e26b8f38b90c2887259d88ce614654f32ecd76ade1438a0def40d360e461d995c796f16a17108fad226793fd4f52ff013428eda3b39cd504ed5f1811d0d"
  }
}
```

### `Edit proposal`

Edit an existent proposal into the politeiawww server.

The Metadata field is required to include a [`Metadata`](#metadata) object that
contains an encoded [`ProposalMetadata`](#proposal-metadata).

Note that updating public proposals will generate a new record version. While
updating an unvetted record will change the record but it will not generate
a new version.

The example shown below is for a public proposal where the proposal version is
increased by one after the update.

**Route:** `POST /v1/proposals/edit`

**Params:**

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| files | array of [`File`](#file)s | Files are the body of the proposal. It should consist of one markdown file - named "index.md" - and up to five pictures. **Note:** all parameters within each [`File`](#file) are required. | Yes |
| metadata | array of [`Metadata`](#metadata) | User specified proposal metadata.  |
| signature | string | Signature of the string representation of the Merkle root of the file payloads and the metadata payloads. Note that the merkle digests are calculated on the decoded payload.. | Yes |
| publickey | string | Public key from the client side, sent to politeiawww for verification | Yes |

**Results:**

| | Type | Description |
|-|-|-|
| proposal | [`Proposal`](#proposal) | The updated proposal. |

**Example:**

Request:

```json
{
   "files":[
      {
         "name":"index.md",
         "mime":"text/plain; charset=utf-8",
         "payload":"RWRpdGVkIHByb3Bvc2FsCmVkaXRlZCBkZXNjcmlwdGlvbg==",
         "digest":"a3c46ac82db1c9e5d780d9ddd046d73a0fdfcb1a2c55ab730f71a4213725e605"
      }
   ],
   "publickey":"1bc17b4aaa7d08030d0cb984d3b67ce7b681508b46ce307b22dfd630141788a0",
   "signature":"e8159f104bb4caa9a7952868ead44af8f1015cac72abd81b1fc83a434e26e0ce75c6a3a8a5c8d8f68405e82eea35c60e2d46fb0ff652eaf53690d57a7d4c8000",
   "token":"6ef01f0ffae69fd267f98756231b8349a14f254c28d2312239cb80579e850337"
}
```

Reply:

```json
{
   "proposal":{
      "name":"Edited proposal",
      "status":4,
      "timestamp":1535468714,
      "publishedat": 1508296860900,
      "censoredat": 0,
      "abandonedat": 0,
      "userid":"",
      "username":"",
      "publickey":"1bc17b4aaa7d08030d0cb984d3b67ce7b681508b46ce307b22dfd630141788a0",
      "signature":"e8159f104bb4caa9a7952868ead44af8f1015cac72abd81b1fc83a434e26e0ce75c6a3a8a5c8d8f68405e82eea35c60e2d46fb0ff652eaf53690d57a7d4c8000",
      "files":[
         {
            "name":"index.md",
            "mime":"text/plain; charset=utf-8",
            "digest":"a3c46ac82db1c9e5d780d9ddd046d73a0fdfcb1a2c55ab730f71a4213725e605",
            "payload":"RWRpdGVkIHByb3Bvc2FsCmVkaXRlZCBkZXNjcmlwdGlvbg=="
         }
      ],
      "numcomments":0,
      "version":"2",
      "censorshiprecord":{
         "token":"6ef01f0ffae69fd267f98756231b8349a14f254c28d2312239cb80579e850337",
         "merkle":"a3c46ac82db1c9e5d780d9ddd046d73a0fdfcb1a2c55ab730f71a4213725e605",
         "signature":"aead575825a8cf3195079e263fe8eeb342f0fe51757e79de7bb8e733c672c0762cd3a0eb58de5057813028244910324d71ffd96d4a809a4c4634883b62a08007"
      }
   }
}
```

### `Vetted`

Retrieve a page of vetted proposals; the number of proposals returned in the
page is limited by the `ProposalListPageSize` property, which is provided via
[`Policy`](#policy).

**Route:** `GET /v1/proposals/vetted`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| before | String | A proposal censorship token; if provided, the page of proposals returned will end right before the proposal whose token is provided, when sorted in reverse chronological order. This parameter should not be specified if `after` is set. | |
| after | String | A proposal censorship token; if provided, the page of proposals returned will begin right after the proposal whose token is provided, when sorted in reverse chronological order. This parameter should not be specified if `before` is set. | |

**Results:**

| | Type | Description |
|-|-|-|
| proposals | Array of [`Proposal`](#proposal)s | An Array of vetted proposals. |

**Example**

Request:

The request params should be provided within the URL:

```
/v1/proposals/vetted?after=f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde
```

Reply:

```json
{
  "proposals": [{
    "name": "My Proposal",
    "status": 4,
    "timestamp": 1508296860781,
    "publishedat": 1508296860900,
    "censoredat": 0,
    "abandonedat": 0,
    "censorshiprecord": {
      "token": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
      "merkle": "0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
      "signature": "fcc92e26b8f38b90c2887259d88ce614654f32ecd76ade1438a0def40d360e461d995c796f16a17108fad226793fd4f52ff013428eda3b39cd504ed5f1811d0d"
    }
  }]
}
```

### `User proposals`

Retrieve a page and the total amount of proposals submitted by the given user; the number of proposals returned in the page is limited by the `proposallistpagesize` property, which is provided via [`Policy`](#policy).

**Route:** `GET /v1/user/proposals`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| userid | String | The user id |
| before | String | A proposal censorship token; if provided, the page of proposals returned will end right before the proposal whose token is provided. This parameter should not be specified if `after` is set. | |
| after | String | A proposal censorship token; if provided, the page of proposals returned will begin right after the proposal whose token is provided. This parameter should not be specified if `before` is set. | |

**Results:**

| | Type | Description |
|-|-|-|
| proposals | array of [`Proposal`](#proposal)s | One page of user submitted proposals. |
| numOfProposals | int | Total number of proposals submitted by the user. If an admin is sending the request or a user is requesting their own proposals then this value includes unvetted, censored, and public proposals. Otherwise, this value only includes public proposals. |

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusUserNotFound`](#ErrorStatusUserNotFound)

**Example**

Request:

The request params should be provided within the URL:

```
/v1/user/proposals?userid=15&after=f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde
```

Reply:

```json
{
  "proposals": [{
    "name": "My Proposal",
    "status": 2,
    "timestamp": 1508296860781,
    "censorshiprecord": {
      "token": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
      "merkle": "0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
      "signature": "fcc92e26b8f38b90c2887259d88ce614654f32ecd76ade1438a0def40d360e461d995c796f16a17108fad226793fd4f52ff013428eda3b39cd504ed5f1811d0d"
    }
  }],
  "numofproposals": 1
}
```

### `Policy`

Retrieve server policy.  The returned values contain various maxima that the
client SHALL observe.

**Route:** `GET /v1/policy`

**Params:** none

**Results:**

| | Type | Description |
|-|-|-|
| minpasswordlength | number | minimum number of characters accepted for user passwords |
| minusernamelength | number | minimum number of characters accepted for username |
| maxusernamelength | number | maximum number of characters accepted for username |
| usernamesupportedchars | array of strings | the regular expression of a valid username |
| paywallenabled | bool | is paywall enabled |
| proposallistpagesize | number | maximum number of proposals returned for the routes that return lists of proposals |
| userlistpagesize | number | maximum number of users returned for the routes that return lists of users |
| maximages | number | maximum number of images accepted when creating a new proposal |
| maximagesize | number | maximum image file size (in bytes) accepted when creating a new proposal |
| maxmds | number | maximum number of markdown files accepted when creating a new proposal |
| maxmdsize | number | maximum markdown file size (in bytes) accepted when creating a new proposal |
| validmimetypes | array of strings | list of all acceptable MIME types that can be communicated between client and server. |
| maxproposalnamelength | number | max length of a proposal name |
| minproposalnamelength | number | min length of a proposal name |
| proposalnamesupportedchars | array of strings | the regular expression of a valid proposal name |
| maxcommentlength | number | maximum number of characters accepted for comments |
| backendpublickey | string |  |
| tokenprefixlength | number | The length of token prefix needed
| buildinformation | []string | build information including module commit hashes |
| IndexFilename | string | required filename for the proposal index.md file |
| MinLinkbyPeriod | number | Minimum required period, in seconds, for the proposal linkby period |
| MaxLinkByPeriod | number | Maximum allowed period, in seconds, for the proposal linkby period |
| MinVoteDuration | number | Minimum allowed vote duration |
| MaxVoteDuration | number | Maximum allowed vote duration |

**Example**

Request:

```
/v1/policy
```

Reply:

```json
{
  "minpasswordlength": 8,
  "minusernamelength": 3,
  "maxusernamelength": 30,
  "usernamesupportedchars": [
    "A-z", "0-9", ".", ":", ";", ",", "-", " ", "@", "+"
  ],
  "proposallistpagesize": 20,
  "maximages": 5,
  "maximagesize": 524288,
  "maxmds": 1,
  "maxmdsize": 524288,
  "validmimetypes": [
    "image/png",
    "text/plain",
    "text/plain; charset=utf-8"
  ],
  "paywallenabled": true,
  "proposalnamesupportedchars": [
     "A-z", "0-9", "&", ".", ":", ";", ",", "-", " ", "@", "+", "#"
  ],
  "maxcommentlength": 8000,
  "backendpublickey": "",
  "minproposalnamelength": 8,
  "maxproposalnamelength": 80,
  "tokenprefixlength": 7,
  "minvoteduration": 2016,
  "maxvoteduration": 4032
}
```

### `Set proposal status`

Update the [status](#proposal-status-codes) of a proposal.  This call requires
admin privileges.

Unvetted proposals can have their status updated to:
`PropStatusPublic`
`PropStatusCensored`

Vetted proposals can have their status updated to:
`PropStatusAbandoned`

A status change message detailing the reason for the status change is required
for the following statuses:
`PropStatusCensored`
`PropStatusAbandoned`

**Route:** `POST /v1/proposals/{token}/status`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| token | string | Token is the unique censorship token that identifies a specific proposal. | Yes |
| proposalstatus | [`proposal status`](#proposal-status-codes) | New proposal status.| Yes |
| statuschangemessage | string |  Reason for status change. | No |
| signature | string | Signature of (token + proposalstatus + statuschangemessage). | Yes |
| publickey | string | Public key that corresponds to the signature. | Yes |

**Results:**

| Parameter | Type | Description |
|-|-|-|
| proposal | [`Proposal`](#proposal) | An entire proposal and it's contents. |

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusChangeMessageCannotBeBlank`](#ErrorStatusChangeMessageCannotBeBlank)
- [`ErrorStatusInvalidSigningKey`](#ErrorStatusInvalidSigningKey)
- [`ErrorStatusInvalidSignature`](#ErrorStatusInvalidSignature)
- [`ErrorStatusProposalNotFound`](#ErrorStatusProposalNotFound)
- [`ErrorStatusReviewerAdminEqualsAuthor`](#ErrorStatusReviewerAdminEqualsAuthor)
- [`ErrorStatusInvalidPropStatusTransition`](#ErrorStatusInvalidPropStatusTransition)

**Example**

Request:

```json
{
  "proposalstatus": 3,
  "publickey": "f5519b6fdee08be45d47d5dd794e81303688a8798012d8983ba3f15af70a747c",
  "signature": "041a12e5df95ec132be27f0c716fd8f7fc23889d05f66a26ef64326bd5d4e8c2bfed660235856da219237d185fb38c6be99125d834c57030428c6b96a2576900",
  "token": "6161819a5df120162ed7b7fa5a95021f9d489a9eaf8b1bb23447fb8a5abc643b"
}
```

Reply:

```json
{
	"proposal": {
		"name": "My Proposal",
		"state": "2",
		"status": 4,
		"timestamp": 1539212044,
		"userid": "",
		"username": "",
		"publickey": "57cf10a15828c633dc0af423669e7bbad2d30a062e4eb1e9c78919f77ebd1022",
		"signature": "553beffb3fece5bdd540e0b83e977e4f68c1ac31e6f2e0a85c3c9aef9e65e3efe3d778edc504a9e88c101f68ad25e677dc3574c67a6e8d0ba711de4b91bec40d",
		"files": [],
		"numcomments": 0,
		"version": "1",
		"censorshiprecord": {
			"token": "fc320c72bb55b6233a8df388109bf494081f007395489a7cdc945e05d656a467",
			"merkle": "ffc1e4b6a1b0b1e8eb99d476aed7ace9ed6475b3bbab9470d01028c24ae51992",
			"signature": "4f409cfb706683e529281033945808cab286917f452ec1594d6f98b8fe2e11206e2b964ac9622c05e8465923f98dd4ee553b3eb08d54f0a3c7ef92f80db16d0a"
		}
	}
}
```

### `Proposal details`

Retrieve proposal and its details. This request can be made with the full
censorship token or its 7 character prefix. This route will return only
vetted proposals.

**Routes:** `GET /v1/proposals/{token}`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| token | string | Token is the unique censorship token that identifies a specific proposal. | Yes |
| version | string | Proposal Version. The latest version is the default when no version is specified. | No |

**Results:**

| | Type | Description |
|-|-|-|
| proposal | [`Proposal`](#proposal) | The proposal with the provided token. |

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusProposalNotFound`](#ErrorStatusProposalNotFound)

**Example**

Request:

The request params should be provided within the URL:

```
/v1/proposals/f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde?version=2
```

Reply:

```json
{
  "proposal": {
    "name": "My Proposal",
    "status": 3,
    "timestamp": 1508146426,
    "version": 2,
    "files": [{
      "name": "index.md",
      "mime": "text/plain; charset=utf-8",
      "digest": "0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
      "payload": "VGhpcyBpcyBhIGRlc2NyaXB0aW9u"
    }],
    "censorshiprecord": {
      "token": "c378e0735b5650c9e79f70113323077b107b0d778547f0d40592955668f21ebf",
      "merkle": "0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
      "signature": "f5ea17d547d8347a2f2d77edcb7e89fcc96613d7aaff1f2a26761779763d77688b57b423f1e7d2da8cd433ef2cfe6f58c7cf1c43065fa6716a03a3726d902d0a"
    }
  }
}
```

### `Batch proposals`

Retrieve the proposal details for a list of proposals.  This route wil not
return the proposal files.  The number of proposals that may be requested is
limited by the `ProposalListPageSize` property, which is provided via
[`Policy`](#policy).  This route will return only vetted proposals.

**Routes:** `POST /v1/proposals/batch`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| tokens | []string | Array of censorship tokens of the proposals to be retrieved | Yes |

**Results:**

| Parameter | Type | Description |
|-|-|-|
| proposals | [][`Proposal`](#proposal) | Array of proposals |

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusMaxProposalsExceededPolicy`](#ErrorStatusMaxProposalsExceededPolicy)
- [`ErrorStatusInvalidCensorshipToken`](#ErrorStatusInvalidCensorshipToken)
- [`ErrorStatusProposalNotFound`](#ErrorStatusProposalNotFound)

**Example**

Request:

```
/v1/proposals/batch
```

```json
{
  "tokens": [
    "c9aaf64f9474a0c2aa2227363e3ba575e1926acd4257deba42dc6d5ab85f2cd2",
    "f08dc22069f854856e27a6cb107e10064a85b85b2a4db41755d54f90bd30b84f"
  ]
}
```

Reply:

```json
{
    "proposals": [
        {
            "name": "Sample proposal 1",
            "state": 2,
            "status": 4,
            "timestamp": 1561637933,
            "userid": "bda3852b-f9e8-49a3-924a-147303b7d6b8",
            "username": "username",
            "publickey": "e008f83793c023321d54f283698c47fb50083489501a8c3b4b020b7c92930cb9",
            "signature": "9c05c50b67c74d7c7e80be702afe123f46ddb417583bcd97674073d0d5ddc35804bec88b01d158bc1ab89bdb21e3cabbb4f290365c375ca226f8652d8dc01602",
            "files": [],
            "numcomments": 0,
            "version": "1",
            "publishedat": 1561637933,
            "censorshiprecord": {
                "token": "c9aaf64f9474a0c2aa2227363e3ba575e1926acd4257deba42dc6d5ab85f2cd2",
                "merkle": "ab7d4fe5d89a1110b0c684d89a48558efaeb0247d13ba8a79200d7fdbde91559",
                "signature": "8860999e0df2b9b7cc727f2ebc6c32fd26a8c9bb7660524fefbf85202ea4e1296699544acdcc723d70708f9f1561007bac1c4d250eb5aa5ebdecea224a8fd105"
            }
        },
        {
            "name": "Sample Proposal 2",
            "state": 2,
            "status": 4,
            "timestamp": 1560824670,
            "userid": "6bd802af-42cc-47af-b1dc-412f93f21689",
            "username": "user2",
            "publickey": "ceaca7ba3579620968a1720e0748f3005802a2fd9e5afe0c7916f79c70234664",
            "signature": "ea41d5f8808892488185d18447f5b8c9d77c0d65932464d5742c1d22dbb0c975b42aaddcb1dae4f5d4a4423f4965c8af4a9273d48faae1f0531abe3039608001",
            "files": [],
            "numcomments": 3,
            "version": "1",
            "publishedat": 1560824670,
            "censorshiprecord": {
                "token": "f08dc22069f854856e27a6cb107e10064a85b85b2a4db41755d54f90bd30b84f",
                "merkle": "34745ec2aee7ba0bf3111c66f8484efb32bfea3bfe6cdcc46420adc1c7d181cc",
                "signature": "f0638afa9466ec3e4954f64e77929a0dd22d05b685180eaf36816e6cd65237760d4485be8afee04b824665acc809856aeabe9eade48f23a99b7be42e4508ac05"
            }
        }
    ]
}
```

### `Batch vote summary`

Retrieve the vote summaries for a list of proposals.  The number of vote
summaries that may be requested is limited by the `ProposalListPageSize`
property, which is provided via [`Policy`](#policy).

**Routes:** `POST /v1/proposals/batchvotesummary`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| tokens | []string | Array of censorship tokens of the requested vote summaries | Yes |

**Results:**

| Parameter | Type | Description |
|-|-|-|
| bestblock | uint64 | Current block height |
| summaries | map[string][`VoteSummary`](#vote-summary) | Map of [token]VoteSummary |

On failure the call shall return `400 Bad Request` on the following error code:
- [`ErrorStatusMaxProposalsExceededPolicy`](#ErrorStatusMaxProposalsExceededPolicy)
- [`ErrorStatusInvalidCensorshipToken`](#ErrorStatusInvalidCensorshipToken)
- [`ErrorStatusProposalNotFound`](#ErrorStatusProposalNotFound)

**Example**

Request:

```
/v1/proposals/batchvotesummary
```

```json
{
  "tokens": [
    "f08dc22069f854856e27a6cb107e10064a85b85b2a4db41755d54f90bd30b84f",
    "c9aaf64f9474a0c2aa2227363e3ba575e1926acd4257deba42dc6d5ab85f2cd2"
  ]
}
```

Reply:

```json
{
  "bestblock": 243994,
  "summaries": {
    "f08dc22069f854856e27a6cb107e10064a85b85b2a4db41755d54f90bd30b84f": {
      "status": 4,
      "eligibletickets": 5267,
      "duration": 2016,
      "endheight": 231614,
      "quorumpercentage": 20,
      "passpercentage": 60,
      "results": [
        {
          "option": {
            "id": "no",
            "description": "Don't approve proposal",
            "bits": 1
          },
          "votesreceived": 3
        },
        {
          "option": {
            "id": "yes",
            "description": "Approve proposal",
            "bits": 2
          },
          "votesreceived": 2
        }
      ]
    },
    "c9aaf64f9474a0c2aa2227363e3ba575e1926acd4257deba42dc6d5ab85f2cd2": {
      "status": 4,
      "eligibletickets": 5270,
      "duration": 2016,
      "endheight": 229602,
      "quorumpercentage": 20,
      "passpercentage": 60,
      "results": [
        {
          "option": {
            "id": "no",
            "description": "Don't approve proposal",
            "bits": 1
          },
          "votesreceived": 1
        },
        {
          "option": {
            "id": "yes",
            "description": "Approve proposal",
            "bits": 2
          },
          "votesreceived": 4
        }
      ]
    }
  }
}
```

### `New comment`

Submit comment on given proposal.  ParentID value "0" means "comment on
proposal"; if the value is not empty it means "reply to comment".

**Route:** `POST /v1/comments/new`

**Params:**

| Parameter | Type | Description | Required |
| - | - | - | - |
| token | string | Censorship token | Yes |
| parentid | string | Parent comment identifier | Yes |
| comment | string | Comment | Yes |
| signature | string | Signature of Token, ParentID and Comment | Yes |
| publickey | string | Public key from the client side, sent to politeiawww for verification | Yes |

**Results:**

| | Type | Description |
| - | - | - |
| token | string | Censorship token |
| parentid | string | Parent comment identifier |
| comment | string | Comment text |
| signature | string | Signature of Token, ParentID and Comment |
| publickey | string | Public key from the client side, sent to politeiawww for verification |
| commentid | string | Unique comment identifier |
| receipt | string | Server signature of the client Signature |
| timestamp | int64 | UNIX time when comment was accepted |
| resultvotes | int64 | Vote score |
| upvotes | uint64 | Pro votes |
| downvotes | uint64 | Contra votes |
| censored | bool | Has the comment been censored |
| userid | string | Unique user identifier |
| username | string | Unique username |

On failure the call shall return `400 Bad Request` and one of the following
error codes:

- [`ErrorStatusUserNotPaid`](#ErrorStatusUserNotPaid)
- [`ErrorStatusInvalidSigningKey`](#ErrorStatusInvalidSigningKey)
- [`ErrorStatusInvalidSignature`](#ErrorStatusInvalidSignature)
- [`ErrorStatusCommentLengthExceededPolicy`](#ErrorStatusCommentLengthExceededPolicy)
- [`ErrorStatusInvalidCensorshipToken`](#ErrorStatusInvalidCensorshipToken)
- [`ErrorStatusProposalNotFound`](#ErrorStatusProposalNotFound)
- [`ErrorStatusWrongStatus`](#ErrorStatusWrongStatus)
- [`ErrorStatusWrongVoteStatus`](#ErrorStatusWrongVoteStatus)
- [`ErrorStatusDuplicateComment`](#ErrorStatusDuplicateComment)

**Example**

Request:

```json
{
  "token":"abf0fd1fc1b8c1c9535685373dce6c54948b7eb018e17e3a8cea26a3c9b85684",
  "parentid":"0",
  "comment":"I dont like this prop",
  "signature":"af969d7f0f711e25cb411bdbbe3268bbf3004075cde8ebaee0fc9d988f24e45013cc2df6762dca5b3eb8abb077f76e0b016380a7eba2d46839b04c507d86290d",
  "publickey":"4206fa1f45c898f1dee487d7a7a82e0ed293858313b8b022a6a88f2bcae6cdd7"
}
```

Reply:

```json
{
  "token": "abf0fd1fc1b8c1c9535685373dce6c54948b7eb018e17e3a8cea26a3c9b85684",
  "parentid": "0",
  "comment": "I dont like this prop",
  "signature":"af969d7f0f711e25cb411bdbbe3268bbf3004075cde8ebaee0fc9d988f24e45013cc2df6762dca5b3eb8abb077f76e0b016380a7eba2d46839b04c507d86290d",
  "publickey": "4206fa1f45c898f1dee487d7a7a82e0ed293858313b8b022a6a88f2bcae6cdd7",
  "commentid": "4",
  "receipt": "96f3956ea3decb75ee129e6ee4e77c6c608f0b5c99ff41960a4e6078d8bb74e8ad9d2545c01fff2f8b7e0af38ee9de406aea8a0b897777d619e93d797bc1650a",
  "timestamp": 1527277504,
  "resultvotes": 0,
  "censored": false,
  "userid": "124",
  "username": "john",
}
```

### `Get comments`

Retrieve all comments for given proposal.  Note that the comments are not
sorted.

**Route:** `GET /v1/proposals/{token}/comments`

**Params:**

**Results:**

| | Type | Description |
| - | - | - |
| Comments | Comment | Unsorted array of all comments |
| AccessTime | int64 | UNIX timestamp of last access time. Omitted if no session cookie is present. |

**Comment:**

| | Type | Description |
| - | - | - |
| userid | string | Unique user identifier |
| username | string | Unique username |
| timestamp | int64 | UNIX time when comment was accepted |
| commentid | string | Unique comment identifier |
| parentid | string | Parent comment identifier |
| token | string | Censorship token |
| comment | string | Comment text |
| publickey | string | Public key from the client side, sent to politeiawww for verification |
| signature | string | Signature of Token, ParentID and Comment |
| receipt | string | Server signature of the client Signature |
| totalvotes | uint64 | Total number of up/down votes |
| resultvotes | int64 | Vote score |
| upvotes | uint64 | Pro votes |
| downvotes | uint64 | Contra votes |

**Example**

Request:

The request params should be provided within the URL:

```
/v1/proposals/f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde/comments
```

Reply:

```json
{
  "comments": [{
    "comment": "I dont like this prop",
    "commentid": "4",
    "parentid": "0",
    "publickey": "4206fa1f45c898f1dee487d7a7a82e0ed293858313b8b022a6a88f2bcae6cdd7",
    "receipt": "96f3956ea3decb75ee129e6ee4e77c6c608f0b5c99ff41960a4e6078d8bb74e8ad9d2545c01fff2f8b7e0af38ee9de406aea8a0b897777d619e93d797bc1650a",
    "signature":"af969d7f0f711e25cb411bdbbe3268bbf3004075cde8ebaee0fc9d988f24e45013cc2df6762dca5b3eb8abb077f76e0b016380a7eba2d46839b04c507d86290d",
    "timestamp": 1527277504,
    "token": "abf0fd1fc1b8c1c9535685373dce6c54948b7eb018e17e3a8cea26a3c9b85684",
    "userid": "124",
    "username": "john",
    "totalvotes": 4,
    "resultvotes": 2,
    "upvotes": 3,
    "downvotes": 1
  },{
    "comment":"you are right!",
    "commentid": "4",
    "parentid": "0",
    "publickey": "4206fa1f45c898f1dee487d7a7a82e0ed293858313b8b022a6a88f2bcae6cdd7",
    "receipt": "96f3956ea3decb75ee129e6ee4e77c6c608f0b5c99ff41960a4e6078d8bb74e8ad9d2545c01fff2f8b7e0af38ee9de406aea8a0b897777d619e93d797bc1650a",
    "signature":"af969d7f0f711e25cb411bdbbe3268bbf3004075cde8ebaee0fc9d988f24e45013cc2df6762dca5b3eb8abb077f76e0b016380a7eba2d46839b04c507d86290d",
    "timestamp": 1527277504,
    "token": "abf0fd1fc1b8c1c9535685373dce6c54948b7eb018e17e3a8cea26a3c9b85684",
    "userid": "124",
    "username": "john",
    "totalvotes": 4,
    "resultvotes": 2,
    "upvotes": 3,
    "downvotes": 1
  },{
    "comment":"you are crazy!",
    "commentid": "4",
    "parentid": "0",
    "publickey": "4206fa1f45c898f1dee487d7a7a82e0ed293858313b8b022a6a88f2bcae6cdd7",
    "receipt": "96f3956ea3decb75ee129e6ee4e77c6c608f0b5c99ff41960a4e6078d8bb74e8ad9d2545c01fff2f8b7e0af38ee9de406aea8a0b897777d619e93d797bc1650a",
    "signature":"af969d7f0f711e25cb411bdbbe3268bbf3004075cde8ebaee0fc9d988f24e45013cc2df6762dca5b3eb8abb077f76e0b016380a7eba2d46839b04c507d86290d",
    "timestamp": 1527277504,
    "token": "abf0fd1fc1b8c1c9535685373dce6c54948b7eb018e17e3a8cea26a3c9b85684",
    "userid": "124",
    "username": "john",
    "totalvotes": 4,
    "resultvotes": 2,
    "upvotes": 3,
    "downvotes": 1
  }],
  "accesstime": 1543539276
}
```

### `Like comment`

Allows a user to up or down vote a comment.  Censored comments cannot be voted
on.

**Route:** `POST v1/comments/like`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| token | string | Censorship token | yes |
| commentid | string | Unique comment identifier | yes |
| action | string | Up or downvote (1, -1) | yes |
| signature | string | Signature of Token, CommentId and Action | yes |
| publickey | string | Public key used for Signature |

**Results:**

| | Type | Description |
|-|-|-|
| total | uint64 | Total number of up and down votes |
| resultvotes | int64 | Vote score |
| upvotes | uint64 | Pro votes |
| downvotes | uint64 | Contra votes |
| receipt | string | Server signature of client signature |
| error | Error if something went wront during liking a comment
**Example:**

Request:

```json
{
  "token": "abf0fd1fc1b8c1c9535685373dce6c54948b7eb018e17e3a8cea26a3c9b85684",
  "commentid": "4",
  "action": "1",
  "signature": "af969d7f0f711e25cb411bdbbe3268bbf3004075cde8ebaee0fc9d988f24e45013cc2df6762dca5b3eb8abb077f76e0b016380a7eba2d46839b04c507d86290d",
  "publickey": "4206fa1f45c898f1dee487d7a7a82e0ed293858313b8b022a6a88f2bcae6cdd7"
}
```

Reply:

```json
{
  "total": 4,
  "result": 2,
  "upvotes": 3,
  "downvotes": 1,
  "receipt": "96f3956ea3decb75ee129e6ee4e77c6c608f0b5c99ff41960a4e6078d8bb74e8ad9d2545c01fff2f8b7e0af38ee9de406aea8a0b897777d619e93d797bc1650a"
}
```

### `Censor comment`

Allows a admin to censor a proposal comment.

**Route:** `POST v1/comments/censor`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| token | string | Censorship token | yes |
| commentid | string | Unique comment identifier | yes |
| reason | string | Reason for censoring the comment | yes |
| signature | string | Signature of Token, CommentId and Reason | yes |
| publickey | string | Public key used for Signature | yes |

**Results:**

| | Type | Description |
|-|-|-|
| receipt | string | Server signature of client signature |

On failure the call shall return `403 Forbidden` and one of the following
error codes:
- [`ErrorStatusUserNotPaid`](#ErrorStatusUserNotPaid)
- [`ErrorStatusInvalidSigningKey`](#ErrorStatusInvalidSigningKey)
- [`ErrorStatusInvalidSignature`](#ErrorStatusInvalidSignature)
- [`ErrorStatusProposalNotFound`](#ErrorStatusProposalNotFound)
- [`ErrorStatusWrongStatus`](#ErrorStatusWrongStatus)
- [`ErrorStatusWrongVoteStatus`](#ErrorStatusWrongVoteStatus)
- [`ErrorStatusCommentNotFound`](#ErrorStatusCommentNotFound)
- [`ErrorStatusCommentIsCensored`](#ErrorStatusCommentIsCensored)
- [`ErrorStatusInvalidLikeCommentAction`](#ErrorStatusInvalidLikeCommentAction)

**Example:**

Request:

```json
{
  "token": "abf0fd1fc1b8c1c9535685373dce6c54948b7eb018e17e3a8cea26a3c9b85684",
  "commentid": "4",
  "reason": "comment was an advertisement",
  "signature": "af969d7f0f711e25cb411bdbbe3268bbf3004075cde8ebaee0fc9d988f24e45013cc2df6762dca5b3eb8abb077f76e0b016380a7eba2d46839b04c507d86290d",
  "publickey": "4206fa1f45c898f1dee487d7a7a82e0ed293858313b8b022a6a88f2bcae6cdd7"
}
```

Reply:

```json
{
  "receipt": "96f3956ea3decb75ee129e6ee4e77c6c608f0b5c99ff41960a4e6078d8bb74e8ad9d2545c01fff2f8b7e0af38ee9de406aea8a0b897777d619e93d797bc1650a"
}
```

### `Authorize vote`

Authorize a proposal vote.  The proposal author must send an authorize vote
request to indicate that the proposal is in its final state and is ready to be
voted on before an admin can start the voting period for the proposal.  The
author can also revoke a previously sent vote authorization.

**Route:** `POST /v1/proposals/authorizevote`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| action | string | The action to be executed (authorize or revoke) | Yes |
| token | string | Proposal censorship token | Yes |
| signature | string | Signature of the token + proposal version | Yes |
| publickey | string | Public key used to sign the vote | Yes |

**Results (StartVoteReply):**

| | Type | Description |
| - | - | - |
| action | string | The action that was executed. | Yes |
| receipt | string | Politeiad signature of the client signature |

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusNoPublicKey`](#ErrorStatusNoPublicKey)
- [`ErrorStatusInvalidSigningKey`](#ErrorStatusInvalidSigningKey)
- [`ErrorStatusInvalidSignature`](#ErrorStatusInvalidSignature)
- [`ErrorStatusWrongStatus`](#ErrorStatusWrongStatus)
- [`ErrorStatusInvalidAuthVoteAction`](#ErrorStatusInvalidAuthVoteAction)
- [`ErrorStatusVoteAlreadyAuthorized`](#ErrorStatusVoteAlreadyAuthorized)
- [`ErrorStatusVoteNotAuthorized`](#ErrorStatusVoteNotAuthorized)
- [`ErrorStatusUserNotAuthor`](#ErrorStatusUserNotAuthor)

**Example**

Request:

``` json
{
  "action": "authorize",
  "token": "657db73bca8afae3b99dd6ab1ac8564f71c7fb55713526e663afc3e9eff89233",
  "signature": "aba600243e9e59927d3270742de25aae002c6c4952ddaf39702c328d855e9895ed9d9f8ee6154511b81c4272c2329e1e0bb2d79fe08626150a11bc78a4eefe00",
  "publickey": "c2c2ea7f24733983bf8037c189f32b5da49e6396b7d21cb69efe09d290b3cb6d"
}
```

Reply:

```json
{
  "action": "authorize",
  "receipt": "2d7846cb3c8383b5db360ef6d1476341f07ab4d4819cdeac0601cfa5b8bca0ecf370402ba65ace249813caad50e7b0b6e92757a2bff94c385f71808bc5574203"
}
```

### `Active votes`

Retrieve all active votes

Note that the webserver does not interpret the plugin structures. These are
forwarded as-is to the politeia daemon.

**Route:** `POST /v1/proposals/activevote`

**Params:**

**Results:**

| | Type | Description |
| - | - | - |
| votes | array of ProposalVoteTuple | All current active votes |

**ProposalVoteTuple:**

| | Type | Description |
| - | - | - |
| proposal | ProposalRecord | Proposal record |
| startvote | Vote | Vote bits, mask etc |
| starvotereply | StartVoteReply | Vote details (eligible tickets, start block etc |

**Example**

Request:

``` json
{}
```

Reply:

```json
{
  "votes": [{
    "proposal": {
      "name":"This is a description",
      "status":4,
      "timestamp":1523902523,
      "userid":"",
      "publickey":"d64d80c36441255e41fc1e7b6cd30259ff9a2b1276c32c7de1b7a832dff7f2c6",
      "signature":"3554f74c112c5da49c6ee1787770c21fe1ae16f7f1205f105e6df1b5bdeaa2439fff6c477445e248e21bcf081c31bbaa96bfe03acace1629494e795e5d296e04",
      "files":[],
      "numcomments":0,
      "censorshiprecord": {
        "token":"8d14c77d9a28a1764832d0fcfb86b6af08f6b327347ab4af4803f9e6f7927225",
        "merkle":"0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
        "signature":"97b1bf0d63d7689a2c6e66e32358d48e98d84e5389f455cc135b3401277d3a37518827da0f2bc892b535937421418e7e8ba6a4f940dfcf19a219867fa8c3e005"
      }
    }
  }],
  "vote": {
    "token":"8d14c77d9a28a1764832d0fcfb86b6af08f6b327347ab4af4803f9e6f7927225",
    "mask":3,
    "duration":2016,
    "Options": [{
      "id":"no",
      "description":"Don't approve proposal",
      "bits":1
    },{
      "id":"yes",
      "description":"Approve proposal",
      "bits":2
    }]
  },
  "votedetails": {
    "startblockheight":"282893",
    "startblockhash":"000000000227ff9b6bf3af53accb81e4fd1690ae44d521a665cb988bcd02ad94",
    "endheight":"284909",
    "eligibletickets": [
      "000011e329fe0359ea1d2070d927c93971232c1118502dddf0b7f1014bf38d97",
      "0004b0f8b2883a2150749b2c8ba05652b02220e98895999fd96df790384888f9",
      "00107166c5fc5c322ecda3748a1896f4a2de6672aae25014123d2cedc83e8f42",
      "002272cf4788c3f726c30472f9c97d2ce66b997b5762ff4df6a05c4761272413"
    ]
  }
}
```

Note: eligibletickets is abbreviated for readability.


### `Cast votes`

This is a batched call that casts multiple votes to multiple proposals.

Note that the webserver does not interpret the plugin structures. These are
forwarded as-is to the politeia daemon.

**Route:** `POST /v1/proposals/castvotes`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| votes | array of CastVote | All votes | Yes |

**CastVote:**

| | Type | Description |
| - | - | - |
| token | string | Censorship token |
| ticket | string | Ticket hash |
| votebit | string | String encoded vote bit |
| signature | string | signature of Token+Ticket+VoteBit |

**Results:**

| | Type | Description |
| - | - | - |
| receipts | array of CastVoteReply  | Receipts for all cast votes. This appears in the same order and index as the votes that went in. |

**CastVoteReply:**

| | Type | Description |
| - | - | - |
| clientsignature | string | Signature that was sent in via CastVote |
| signature | string | Signature of ClientSignature |
| error | string | Error, "" if there was no error |

**Example**

Request:

``` json
{
  "votes": [{
    "token":"642eb2f3798090b3234d8787aaba046f1f4409436d40994643213b63cb3f41da",
    "ticket":"1257089bfa5223739c27dd10150de71962442f57ee176389c79932c22536b31b",
    "votebit":"2",
    "signature":"1f05c95fd0c59b0ee68733bbc645437124702e2af40fe37f01f15784a161b8ebae432fcfc5c9388e8f7409e6f02976182eda3bffa5df5de968f40faf2d993a9992"
    },{
      "token":"642eb2f3798090b3234d8787aaba046f1f4409436d40994643213b63cb3f41da",
      "ticket":"1c1e0b6968813f8321e721598f9510afae6acaa8576b64297e34fd5777d8d417",
      "votebit":"2",
      "signature":"1ff92d0025ea7ff283e4991b6fcdd6c87958f5ba5ba34863c075650a8b16dc23906f639ab83d034d6146de109afca7c0c92a00c60f36640846f679fb6ff2d7f966"
    }
  ]
}
```

Reply:

```json
{
  "receipts": [{
    "clientsignature":"1f05c95fd0c59b0ee68733bbc645437124702e2af40fe37f01f15784a161b8ebae432fcfc5c9388e8f7409e6f02976182eda3bffa5df5de968f40faf2d993a9992",
    "signature":"1bc19bf3ee2da7b0a9a54ae944e42e7b9e8953fce0c122b0a0a540e900535ea7ae3c5f2bba8266025d797b0dd4e37f0d21ed2f974b246528ae162a3719ed0808",
    "error":""
  },{
    "clientsignature":"1ff92d0025ea7ff283e4991b6fcdd6c87958f5ba5ba34863c075650a8b16dc23906f639ab83d034d6146de109afca7c0c92a00c60f36640846f679fb6ff2d7f966",
    "signature":"dbd24b1205c3c81a1d8a5736d769e1d6fd37ea517c15934e4b2042df65567e8c4029137eec8fb03fdcf40ecfe5a5eaa2bd36f485c6597328f543d5c283de5e0a",
    "error":""
  }]
}
```

### `Vote results`

Retrieve vote results for a specified censorship token. If the voting period
has not yet started for the given proposal a reply is returned with all fields
set to their zero value.

Note that the webserver does not interpret the plugin structures. These are
forwarded as-is to the politeia daemon.

**Route:** `GET /v1/proposals/{token}/votes`

**Params:** none

**Results:**

| | Type | Description |
| - | - | - |
| vote | Vote | Vote details |
| castvotes | array of CastVote  | Cast vote details |
| startvotereply | StartVoteReply | Vote details (eligible tickets, start block etc) |


On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusProposalNotFound`](#ErrorStatusProposalNotFound)
- [`ErrorStatusWrongStatus`](#ErrorStatusWrongStatus)

**Example**

Request:
`GET /V1/proposals/642eb2f3798090b3234d8787aaba046f1f4409436d40994643213b63cb3f41da/votes`


Reply:

```json
{
  "vote": {
    "token":"642eb2f3798090b3234d8787aaba046f1f4409436d40994643213b63cb3f41da",
    "mask":3,
    "duration":2016,
    "Options": [{
      "id":"no",
      "description":"Don't approve proposal",
      "bits":1
    },{
      "id":"yes",
      "description":"Approve proposal",
      "bits":2
    }]
  },
  "castvotes": [{
    "token":"642eb2f3798090b3234d8787aaba046f1f4409436d40994643213b63cb3f41da",
    "ticket":"91832123c3f04c0783fb51d93bffd6f641ce3e951c30a29e15fb9986f23817c0",
    "votebit":"2",
    "signature":"208e614662fd7719df82687b72578cfb1f5e54fd05287e67683397b77e1819d4ff5c2029117d1d01bfa5c4637b7661ad95319f455c264ed4b4637382ffee5d5d9e"
  },{
    "token":"642eb2f3798090b3234d8787aaba046f1f4409436d40994643213b63cb3f41da",
    "ticket":"cf3943767a35136252f69118b291b47006308e4215de41673ab118736e26605e",
    "votebit":"2",
    "signature":"1f8b3c8207fa67d91a65d8742e5026044ccebd6b4865579a1f75d6e9a40a56f9a96e091397d2ec9f8fca773c68e961b93fe380a694aceecfd8f9b972f1e4d59db9"
  }],
  "startvotereply": {
    "startblockheight":"282899",
    "startblockhash":"00000000017236b62ff1ce136328e6fb4bcd171801a281ce0a662e63cbc4c4fa",
    "endheight":"284915",
    "eligibletickets":[
      "000011e329fe0359ea1d2070d927c93971232c1118502dddf0b7f1014bf38d97",
      "0004b0f8b2883a2150749b2c8ba05652b02220e98895999fd96df790384888f9",
      "00107166c5fc5c322ecda3748a1896f4a2de6672aae25014123d2cedc83e8f42",
      "002272cf4788c3f726c30472f9c97d2ce66b997b5762ff4df6a05c4761272413"
    ]
  }
}
```

### `Proposal vote status`

**This route deprecated by [`Batch Vote Status`](#batch-vote-status).**

Returns the vote status for a single public proposal.

**Route:** `GET /V1/proposals/{token}/votestatus`

**Params:** none

**Result:**

| | Type | Description |
|-|-|-|
| token | string  | Censorship token |
| status | int | Status identifier |
| optionsresult | array of VoteOptionResult | Option description along with the number of votes it has received |
| totalvotes | int | Proposal's total number of votes |
| bestblock | string | The current chain height |
| endheight | string | The chain height in which the vote will end |
| numofeligiblevotes | int | Total number of eligible votes |
| quorumpercentage | uint32 | Percent of eligible votes required for quorum |
| passpercentage | uint32 | Percent of total votes required to pass |

**VoteOptionResult:**

| | Type | Description |
|-|-|-|
| option | VoteOption  | Option description |
| votesreceived | uint64 | Number of votes received |


**Proposal vote status map:**

| status | value |
|-|-|
| Vote status invalid | 0 |
| Vote status not started | 1 |
| Vote status started | 2 |
| Vote status finished | 3 |
| Vote status doesn't exist | 4 |

**Example:**

Request:

`GET /V1/proposals/b09dc5ac9d450b4d1ec6e8f80c763771f29413a5d1bf287054fc00c52ccc87c9/votestatus`

Reply:

```json
{
  "token":"b09dc5ac9d450b4d1ec6e8f80c763771f29413a5d1bf287054fc00c52ccc87c9",
  "status":0,
  "totalvotes":0,
  "optionsresult":[
    {
        "option":{
          "id":"no",
          "description":"Don't approve proposal",
          "bits":1
        },
        "votesreceived":0
    },
    {
        "option":{
          "id":"yes",
          "description":"Approve proposal",
          "bits":2
        },
        "votesreceived":0
    }
  ],
  "bestblock": "45391",
  "endheight": "45567",
  "numofeligiblevotes": 2000,
  "quorumpercentage": 20,
  "passpercentage": 60
}
```

### `Proposals vote status`

**This route deprecated by [`Batch Vote Status`](#batch-vote-status).**

Returns the vote status of all public proposals.

**Route:** `GET /V1/proposals/votestatus`

**Params:** none

**Result:**

| | Type | Description |
|-|-|-|
| votesstatus | array of VoteStatusReply  | Vote status of each public proposal |

**VoteStatusReply:**

| | Type | Description |
|-|-|-|
| token | string  | Censorship token |
| status | int | Status identifier |
| optionsresult | array of VoteOptionResult | Option description along with the number of votes it has received |
| totalvotes | int | Proposal's total number of votes |
| endheight | string | The chain height in which the vote will end |
| bestblock | string | The current chain height |
| numofeligiblevotes | int | Total number of eligible votes |
| quorumpercentage | uint32 | Percent of eligible votes required for quorum |
| passpercentage | uint32 | Percent of total votes required to pass |

**Example:**

Request:

`GET /V1/proposals/votestatus`

Reply:

```json
{
   "votesstatus":[
      {
         "token":"427af6d79f495e8dad2fb0a2a47594daa505b9fbfbd084f13678fa91882aef9f",
         "status":2,
         "optionsresult":[
            {
               "option":{
                  "id":"no",
                  "description":"Don't approve proposal",
                  "bits":1
               },
               "votesreceived":0
            },
            {
               "option":{
                  "id":"yes",
                  "description":"Approve proposal",
                  "bits":2
               },
               "votesreceived":0
            }
         ],
         "totalvotes":0,
         "bestblock": "45392",
         "endheight": "45567",
         "numofeligiblevotes": 2000,
         "quorumpercentage": 20,
         "passpercentage": 60
      },
      {
         "token":"b6d058cd1eed03d7fc9400f55384a8da33edb73743b7501d354392a6f9885078",
         "status":1,
         "optionsresult":null,
         "totalvotes":0,
         "bestblock": "45392",
         "endheight": "",
         "numofeligiblevotes": 0,
         "quorumpercentage": 0,
         "passpercentage": 0
      }
   ]
}
```

### `User Comments Likes`

Retrieve the comment votes for the current logged in user given a proposal token

**Route:** `GET v1/user/proposals/{token}/commentslikes`

**Params:** none

**Results:**

| | Type | Description |
| - | - | - |
| commentslikes | array of CommentLike | Likes issued by the current user |

**CommentLike:**

| | Type | Description |
| - | - | - |
| action | string | Up or downvote (1, -1) |
| commentid | string | Comment ID |
| token | string | Proposal censorship token |

**Example:**

Request:
Path: `v1/user/proposals/8a11057fb910564a7d2506430505c3991f59e35f8a7757b8000a032505b254d8/commentslikes`

Reply:
```json
  {
    "commentslikes":
    [
      {
        "action":"-1",
        "commentid":"1",
        "token":"8a11057fb910564a7d2506430505c3991f59e35f8a7757b8000a032505b254d8"
      },
      {
        "action":"1",
        "commentid":"2",
        "token":"8a11057fb910564a7d2506430505c3991f59e35f8a7757b8000a032505b254d8"
      }
    ]
  }
```

### `Token inventory`

Retrieve the censorship record tokens of all proposals in the inventory. The
tokens are categorized by stage of the voting process and sorted according to
the rules listed below. Unvetted proposal tokens are only returned to admins.
Unvetted proposals include unvreviewed and censored proposals.

Sorted by record timestamp in descending order:
Pre, Abandonded, Unreviewed, Censored

Sorted by voting period end block height in descending order:
Active, Approved, Rejected

**Route:** `GET v1/proposals/tokeninventory`

**Params:** none

**Results:**

| | Type | Description |
| - | - | - |
| pre | []string | Tokens of all vetted proposals that are pre-vote. |
| active | []string | Tokens of all vetted proposals with an active voting period. |
| approved | []string | Tokens of all vetted proposals that have been approved by a vote. |
| rejected | []string | Tokens of all vetted proposals that have been rejected by a vote. |
| abandoned | []string | Tokens of all vetted proposals that have been abandoned. |
| unreviewed | []string | Tokens of all unreviewed proposals. |
| censored | []string | Tokens of all censored proposals. |

**Example:**
Request:
Path: `v1/proposals/tokeninventory`

Reply:

```json
{
  "pre": [
    "567ec4cdca78362f725dbb2b8b5161991fe6ba3bb6da1ad3f99067dd4712e48e"
  ],
  "active": [
    "79cb792d8a15e83ce6809b2846f4dfdd04a65f5aa674c04926599fabf80c1b62"
  ],
  "approved": [],
  "rejected": [],
  "abandoned": [
    "99376fbf7b79e30a7ff778743da46e04ae3b360109fa71011930f4c9a15c4ef5"
  ]
}
```

### `Set TOTP`

This user route requests a new TOTP secret to be generated by the server.  It
will return a Key/Image pair that can be used to save the key pair to
a TOTP app of the users' choice. 

If the user already has a TOTP set, they must also add a code generated from
the currently set secret.

For now we just have 'basic' TOTP added, but in the future we can add different 
or custom types of TOTP.

**Route:** `POST /v1/user/totp`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| type | TOTPMethodT | The type of TOTP that the user wants generated | Yes |
| code | string | A code generated by | Yes |

**Results:** 

| | Type | Description |
| - | - | - |
| key | string | The secret key generated by the server. |
| image | string | The 'image' of the secret that can be used to generate a QRcode. |

On success the call shall return `200 OK`.

On failure the call shall return `400 Bad Request` and one of the following error codes:
- [`ErrorStatusTOTPFailedValidation`](#ErrorStatusTOTPFailedValidation)
- [`ErrorStatusInvalidInput`](#ErrorStatusInvalidInput)

**Example:**

Request:

```json
{
  "type":"1",
  "code":"994411"
}
```

Reply:

```json
{
  "key":"",
  "image":"",
}
```

### `Verify TOTP`

This verify and confirms the user's previous requested new TOTP secret with a
code generated by their TOTP app with the secret key provided from the SetTOTP 
request.

**Route:** `POST /v1/user/verifytotp`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| code | string | The TOTP code generate from the user's secret key. | Yes |

**Results:** none

On success the call shall return `200 OK`.

On failure the call shall return `400 Bad Request` and one of the following error codes:
- [`ErrorStatusTOTPFailedValidation`](#ErrorStatusTOTPFailedValidation)

**Example:**

Request:

The request params should be provided within the URL:

```json
{
  "code":"994411"
}
```

Reply:

```json
{}
```

### `Error codes`

| Status | Value | Description |
|-|-|-|
| <a name="ErrorStatusInvalid">ErrorStatusInvalid</a> | 0 | The operation returned an invalid status. This shall be considered a bug. |
| <a name="ErrorStatusInvalidPassword">ErrorStatusInvalidPassword</a> | 1 | The password is invalid. |
| <a name="ErrorStatusMalformedEmail">ErrorStatusMalformedEmail</a> | 2 | The provided email address was malformed. |
| <a name="ErrorStatusVerificationTokenInvalid">ErrorStatusVerificationTokenInvalid</a> | 3 | The provided user activation token is invalid. |
| <a name="ErrorStatusVerificationTokenExpired">ErrorStatusVerificationTokenExpired</a> | 4 | The provided user activation token is expired. |
| <a name="ErrorStatusProposalMissingFiles">ErrorStatusProposalMissingFiles</a> | 5 | The provided proposal does not have files. This error may include additional context: index file is missing - "index.md". |
| <a name="ErrorStatusProposalNotFound">ErrorStatusProposalNotFound</a> | 6 | The requested proposal does not exist. |
| <a name="ErrorStatusProposalDuplicateFilenames">ErrorStatusProposalDuplicateFilenames</a> | 7 | The provided proposal has duplicate files. This error is provided with additional context: the duplicate name(s). |
| <a name="ErrorStatusProposalInvalidTitle">ErrorStatusProposalInvalidTitle</a> | 8 | The provided proposal title is invalid. This error is provided with additional context: the regular expression accepted. |
| <a name="ErrorStatusMaxMDsExceededPolicy">ErrorStatusMaxMDsExceededPolicy</a> | 9 | The submitted proposal has too many markdown files. Limits can be obtained by issuing the [Policy](#policy) command. |
| <a name="ErrorStatusMaxImagesExceededPolicy">ErrorStatusMaxImagesExceededPolicy</a> | 10 | The submitted proposal has too many images. Limits can be obtained by issuing the [Policy](#policy) command. |
| <a name="ErrorStatusMaxMDSizeExceededPolicy">ErrorStatusMaxMDSizeExceededPolicy</a> | 11 | The submitted proposal markdown is too large. Limits can be obtained by issuing the [Policy](#policy) command. |
| <a name="ErrorStatusMaxImageSizeExceededPolicy">ErrorStatusMaxImageSizeExceededPolicy</a> | 12 | The submitted proposal has one or more images that are too large. Limits can be obtained by issuing the [Policy](#policy) command. |
| <a name="ErrorStatusMalformedPassword">ErrorStatusMalformedPassword</a> | 13 | The provided password was malformed. |
| <a name="ErrorStatusCommentNotFound">ErrorStatusCommentNotFound</a> | 14 | The requested comment does not exist. |
| <a name="ErrorStatusInvalidFilename">ErrorStatusInvalidFilename</a> | 15 | The filename was invalid. |
| <a name="ErrorStatusInvalidFileDigest">ErrorStatusInvalidFileDigest</a> | 16 | The digest (SHA-256 checksum) provided for one of the proposal files was incorrect. This error is provided with additional context: The name of the file with the invalid digest. |
| <a name="ErrorStatusInvalidBase64">ErrorStatusInvalidBase64</a> | 17 | The name of the file with the invalid encoding.The Base64 encoding provided for one of the proposal files was incorrect. This error is provided with additional context: the name of the file with the invalid encoding. |
| <a name="ErrorStatusInvalidMIMEType">ErrorStatusInvalidMIMEType</a> | 18 | The MIME type provided for one of the proposal files was not the same as the one derived from the file's content. This error is provided with additional context: The name of the file with the invalid MIME type and the MIME type detected for the file's content. |
| <a name="ErrorStatusUnsupportedMIMEType">ErrorStatusUnsupportedMIMEType</a> | 19 | The MIME type provided for one of the proposal files is not supported. This error is provided with additional context: The name of the file with the unsupported MIME type and the MIME type that is unsupported. |
| <a name="ErrorStatusInvalidPropStatusTransition">ErrorStatusInvalidPropStatusTransition</a> | 20 | The provided proposal cannot be changed to the given status. |
| <a name="ErrorStatusInvalidPublicKey">ErrorStatusInvalidPublicKey</a> | 21 | Invalid public key. |
| <a name="ErrorStatusNoPublicKey">ErrorStatusNoPublicKey</a> | 22 | User does not have an active public key. |
| <a name="ErrorStatusInvalidSignature">ErrorStatusInvalidSignature</a> | 23 | Invalid signature. |
| <a name="ErrorStatusInvalidInput">ErrorStatusInvalidInput</a> | 24 | Invalid input. |
| <a name="ErrorStatusInvalidSigningKey">ErrorStatusInvalidSigningKey</a> | 25 | Invalid signing key. |
| <a name="ErrorStatusCommentLengthExceededPolicy">ErrorStatusCommentLengthExceededPolicy</a> | 26 | The submitted comment length is too large. |
| <a name="ErrorStatusUserNotFound">ErrorStatusUserNotFound</a> | 27 | The user was not found. |
| <a name="ErrorStatusWrongStatus">ErrorStatusWrongStatus</a> | 28 | The proposal has the wrong status. |
| <a name="ErrorStatusNotLoggedIn">ErrorStatusNotLoggedIn</a> | 29 | The user must be logged in for this action. |
| <a name="ErrorStatusUserNotPaid">ErrorStatusUserNotPaid</a> | 30 | The user hasn't paid the registration fee. |
| <a name="ErrorStatusReviewerAdminEqualsAuthor">ErrorStatusReviewerAdminEqualsAuthor</a> | 31 | The user cannot change the status of his own proposal. |
| <a name="ErrorStatusMalformedUsername">ErrorStatusMalformedUsername</a> | 32 | The provided username was malformed. |
| <a name="ErrorStatusDuplicateUsername">ErrorStatusDuplicateUsername</a> | 33 | The provided username is already taken by another user. |
| <a name="ErrorStatusVerificationTokenUnexpired">ErrorStatusVerificationTokenUnexpired</a> | 34 | A verification token has already been generated and hasn't expired yet. |
| <a name="ErrorStatusCannotVerifyPayment">ErrorStatusCannotVerifyPayment</a> | 35 | The server cannot verify the payment at this time, please try again later. |
| <a name="ErrorStatusDuplicatePublicKey">ErrorStatusDuplicatePublicKey</a> | 36 | The public key provided is already taken by another user. |
| <a name="ErrorStatusInvalidPropVoteStatus">ErrorStatusInvalidPropVoteStatus</a> | 37 | Invalid proposal vote status. |
| <a name="ErrorStatusUserLocked">ErrorStatusUserLocked</a> | 38 | User locked due to too many login attempts. |
| <a name="ErrorStatusNoProposalCredits">ErrorStatusNoProposalCredits</a> | 39 | No proposal credits. |
| <a name="ErrorStatusInvalidUserManageAction">ErrorStatusInvalidUserManageAction</a> | 40 | Invalid action for editing a user. |
| <a name="ErrorStatusUserActionNotAllowed">ErrorStatusUserActionNotAllowed</a> | 41 | User action is not allowed. |
| <a name="ErrorStatusWrongVoteStatus">ErrorStatusWrongVoteStatus</a> | 42 | The proposal has the wrong vote status for the action to be performed. |
| <a name="ErrorStatusCannotVoteOnPropComment">ErrorStatusCannotVoteOnPropComment</a> | 44 | Cannot vote on proposal comment. |
| <a name="ErrorStatusChangeMessageCannotBeBlank">ErrorStatusChangeMessageCannotBeBlank</a> | 45 | Status change message cannot be blank. |
| <a name="ErrorStatusCensorReasonCannotBeBlank">ErrorStatusCensorReasonCannotBeBlank</a> | 46 | Censor comment reason cannot be blank. |
| <a name="ErrorStatusCannotCensorComment">ErrorStatusCannotCensorComment</a> | 47 | Cannot censor comment. |
| <a name="ErrorStatusUserNotAuthor">ErrorStatusUserNotAuthor</a> | 48 | User is not the proposal author. |
| <a name="ErrorStatusVoteNotAuthorized">ErrorStatusVoteNotAuthorized</a> | 49 | Vote has not been authorized. |
| <a name="ErrorStatusVoteAlreadyAuthorized">ErrorStatusVoteAlreadyAuthorized</a> | 50 | Vote has already been authorized. |
| <a name="ErrorStatusInvalidAuthVoteAction">ErrorStatusInvalidAuthVoteAction</a> | 51 | Invalid authorize vote action. |
| <a name="ErrorStatusUserDeactivated">ErrorStatusUserDeactivated</a> | 52 | Cannot login because user account is deactivated. |
| <a name="ErrorStatusInvalidPropVoteBits">ErrorStatusInvalidPropVoteBits</a> | 53 | Invalid proposal vote option bits. |
| <a name="ErrorStatusInvalidPropVoteParams">ErrorStatusInvalidPropVoteParams</a> | 54 | Invalid proposal vote parameters. |
| <a name="ErrorStatusEmailNotVerified">ErrorStatusEmailNotVerified</a> | 55 | Cannot login because user's email is not yet verified. |
| <a name="ErrorStatusInvalidUUID">ErrorStatusInvalidUUID</a> | 56 | Invalid user UUID. |
| <a name="ErrorStatusInvalidLikeCommentAction">ErrorStatusInvalidLikeCommentAction</a> | 57 | Invalid like comment action. |
| <a name="ErrorStatusInvalidCensorshipToken">ErrorStatusInvalidCensorshipToken</a> | 58 | Invalid proposal censorship token. |
| <a name="ErrorStatusEmailAlreadyVerified">ErrorStatusEmailAlreadyVerified</a> | 59 | Email address is already verified. |
| <a name="ErrorStatusNoProposalChanges">ErrorStatusNoProposalChanges</a> | 60 | No changes found in proposal. |
| <a name="ErrorStatusMaxProposalsExceedsPolicy">ErrorStatusMaxProposalsExceededPolicy</a> | 61 | Number of proposals requested exceeded the ProposalListPageSize. |
| <a name="ErrorStatusDuplicateComment">ErrorStatusDuplicateComment</a> | 62 | Duplicate comment. |
| <a name="ErrorStatusInvalidLogin">ErrorStatusInvalidLogin</a> | 63 | Invalid login credentials. |
| <a name="ErrorStatusCommentIsCensored">ErrorStatusCommentIsCensored</a> | 64 | Comment is censored. |
| <a name="ErrorStatusInvalidProposalVersion">ErrorStatusInvalidProposalVersion</a> | 65 | Invalid proposal version.  |
| <a name="ErrorStatusMetadataInvalid">ErrorStatusMetadataInvalid</a> | 66 | Invalid proposal metadata.  |
| <a name="ErrorStatusMetadataMissing">ErrorStatusMetadataMissing</a> | 67 | Missing proposal metadata. |
| <a name="ErrorStatusMetadataDigestInvalid">ErrorStatusMetadataDigestInvalid</a> | 68 | Proposal metadata digest invalid.  |
| <a name="ErrorStatusInvalidVoteType">ErrorStatusInvalidVoteType</a> | 69 | Invalid vote type. |
| <a name="ErrorStatusInvalidVoteOptions">ErrorStatusInvalidVoteOptions</a> | 70 | Invalid vote option.  |
| <a name="ErrorStatusLinkByDeadlineNotMet">ErrorStatusLinkByDeadlineNotMet</a> | 71 | Linkby not met yet.  |
| <a name="ErrorStatusNoLinkedProposals">ErrorStatusNoLinkedProposals</a> | 72 | No linked proposals.  |
| <a name="ErrorStatusInvalidLinkTo">ErrorStatusInvalidLinkTo</a> | 73 | Invalid propsoal linkto. |
| <a name="ErrorStatusInvalidLinkBy">ErrorStatusInvalidLinkBy</a> | 74 | Invalid proposal linkby.  |
| <a name="ErrorStatusInvalidRunoffVote">ErrorStatusInvalidRunoffVote</a> | 75 | Invalid runoff vote. |
| <a name="ErrorStatusWrongProposalType">ErrorStatusWrongProposalType</a> | 76 | Wrong proposal type. |
| <a name="ErrorStatusTOTPFailedValidation">ErrorStatusTOTPFailedValidation</a> | 77 | TOTP code provided doesn't failed validation with current key. |
| <a name="ErrorStatusTOTPInvalidType">ErrorStatusTOTPInvalidType</a> | 78 | Invalid TOTP Type. |


### `Proposal status codes`

| Status | Value | Description |
|-|-|-|
| <a name="PropStatusInvalid">PropStatusInvalid</a>| 0 | An invalid status. This shall be considered a bug. |
| <a name="PropStatusNotFound">PropStatusNotFound</a> | 1 | The proposal was not found. |
| <a name="PropStatusNotReviewed">PropStatusNotReviewed</a> | 2 | The proposal has not been reviewed by an admin. |
| <a name="PropStatusCensored">PropStatusCensored</a> | 3 | The proposal has been censored by an admin. |
| <a name="PropStatusPublic">PropStatusPublic</a> | 4 | The proposal has been published by an admin. |
| <a name="PropStatusUnreviewedChanges">PropStatusUnreviewedChanges</a> | 5 | The proposal has not been rewieved by an admin yet and has been edited by the author. |
| <a name="PropStatusAbandoned">PropStatusAbandoned</a> | 6 | The proposal is public and has been deemed abandoned by an admin. |

### `Vote types`
| Status | Value | Description |
|-|-|-|
| <a name="VoteTypeInvalid">VoteTypeInvalid</a>| 0 | An invalid vote type. This shall be considered a bug. |
| <a name="VoteTypeStandard">VoteTypeStandard</a>| 1 | A simple approve or reject proposal vote where the winner is the voting option that has met the specified pass and quorum requirements. |
| <a name="VoteTypeRunoff">VoteType</a>| 2 | A runoff vote that multiple proposals compete in. All proposals are voted on like normal, but there can only be one winner in a runoff vote. The winner is the proposal that meets the quorum requirement, meets the pass requirement, and that has the most net yes votes. The winning proposal is considered approved and all other proposals are considered rejected. If no proposals meet the quorum and pass requirements then all proposals are considered rejected. Note: in a runoff vote it is possible for a proposal to meet the quorum and pass requirements but still be rejected if it does not have the most net yes votes. |

### `User edit actions`

| Status | Value | Description |
|-|-|-|
| <a name="UserManageInvalid">UserManageInvalid</a>| 0 | An invalid action. This shall be considered a bug. |
| <a name="UserManageExpireNewUserVerification">UserManageExpireNewUserVerification</a> | 1 | Expires the new user verification token. |
| <a name="UserManageExpireUpdateKeyVerification">UserManageExpireUpdateKeyVerification</a> | 2 | Expires the update key verification token. |
| <a name="UserManageExpireResetPasswordVerification">UserManageExpireResetPasswordVerification</a> | 3 | Expires the reset password verification token. |
| <a name="UserManageClearUserPaywall">UserManageClearUserPaywall</a> | 4 | Clears the user's paywall. |
| <a name="UserManageUnlock">UserManageUnlock</a> | 5 | Unlocks a user's account. |
| <a name="UserManageDeactivate">UserManageDeactivate</a> | 6 | Deactivates a user's account so that they are unable to login. |
| <a name="UserManageReactivate">UserManageReactivate</a> | 7 | Reactivates a user's account. |

### `User`

| | Type | Description |
|-|-|-|
| id | string | The unique id of the user. |
| email | string | Email address. |
| username | string | Unique username. |
| isadmin | boolean | Whether the user is an admin or not. |
| newuserpaywalladdress | string | The address in which to send the transaction containing the `newuserpaywallamount`.  If the user has already paid, this field will be empty or not present. |
| newuserpaywallamount | int64 | The amount of DCR (in atoms) to send to `newuserpaywalladdress`.  If the user has already paid, this field will be empty or not present. |
| newuserpaywalltxnotbefore | int64 | The minimum UNIX time (in seconds) required for the block containing the transaction sent to `newuserpaywalladdress`.  If the user has already paid, this field will be empty or not present. |
| newuserpaywalltx | string | The transaction used to pay the `newuserpaywallamount` at `newuserpaywalladdress`. |
| newuserpaywallpollexpiry | int64 | The UNIX time (in seconds) for when the server will stop polling the server for transactions at `newuserpaywalladdress`. |
| newuserverificationtoken | string | The verification token which is sent to the user's email address. |
| newuserverificationexpiry | int64 | The UNIX time (in seconds) for when the `newuserverificationtoken` expires. |
| updatekeyverificationtoken | string | The verification token which is sent to the user's email address. |
| updatekeyverificationexpiry | int64 | The UNIX time (in seconds) for when the `updatekeyverificationtoken` expires. |
| resetpasswordverificationtoken | string | The verification token which is sent to the user's email address. |
| resetpasswordverificationexpiry | int64 | The UNIX time (in seconds) for when the `resetpasswordverificationtoken` expires. |
| lastlogintime | int64 | The UNIX timestamp of the last login date; it will be 0 if the user has not logged in before. |
| failedloginattempts | uint64 | The number of consecutive failed login attempts. |
| islocked | boolean | Whether the user account is locked due to too many failed login attempts. |
| isdeactivated | boolean | Whether the user account is deactivated. Deactivated accounts cannot login. |
| identities | array of [`Identity`](#identity)s | Identities, both activated and deactivated, of the user. |
| proposalcredits | uint64 | The number of available proposal credits the user has. |
| emailnotifications | uint64 | A flag storing the user's preferences for email notifications. Individual notification preferences are stored in bits of the number, and are [documented below](#emailnotifications). |

### `Email notifications`

These are the available email notifications that can be sent.

| Description | Value |
|-|-|
| **For my proposals** |
| Proposal status change (approved/censored) | `1 << 0` |
| Proposal vote started | `1 << 1` |
| **For others' proposals** |
| New proposal published | `1 << 2` |
| Proposal edited | `1 << 3` |
| Proposal vote started | `1 << 4` |
| **Admins for others' proposals** |
| Proposal submitted for review | `1 << 5` |
| Proposal vote authorized | `1 << 6` |

### `Abridged User`

This is a shortened representation of a user, used for lists.

| | Type | Description |
|-|-|-|
| id | string | The unique id of the user. |
| email | string | Email address. |
| username | string | Unique username. |

### `Proposal`

| | Type | Description |
|-|-|-|
| name | string | The name of the proposal. |
| state | number | Current state of the proposal. |
| status | number | Current status of the proposal. |
| timestamp | number | The unix time of the last update of the proposal. |
| userid | string | The ID of the user who created the proposal. |
| username | string | Proposal author's username. |
| publickey | string | The public key of the user who created the proposal. |
| signature | string | The signature of the merkle root, signed by the user who created the proposal. |
| numcomments | number | The number of comments on the proposal. This should be ignored for proposals which are not public. |
| version | string | The proposal version. |
| statatuschangemessage | string | Message associated to the status change (omitempty). |
| pubishedat | number | The timestamp of when the proposal was published (omitempty). |
| censoredat | number | The timestamp of when the proposal was censored (omitempty). |
| abandonedat | The timestamp of when the proposal was abandoned (omitempty). |
| linkto | string | Censorship token of proposal to link to (omitempty). |
| linkby | number | Unix timestamp of RFP link by deadline (omitempty). |
| files | [][`File`](#file)s | Proposal files. This property will only be populated for the [`Proposal details`](#proposal-details) call. |
| metadata | [][`Metadata`](#metadata) | Proposal metadata. This will contain a [`ProposalMetadata`](#proposal-metadata). |
| censorshiprecord | [`CensorshipRecord`](#censorship-record) | The censorship record that was created when the proposal was submitted. |

### `Identity`

| | Type | Description |
|-|-|-|
| pubkey | string | The user's public key. |
| isactive | boolean | Whether or not the identity is active. |

### `File`

| | Type | Description |
|-|-|-|
| name | string | Name is the suggested filename. There should be no filenames that are overlapping and the name shall be validated before being used. |
| mime | string | MIME type of the payload. Currently the system only supports md and png files. The server shall reject invalid MIME types. |
| digest | string | Digest is a SHA256 digest of the payload. The digest shall be verified by politeiad. |
| payload | string | Payload is the actual file content. It shall be base64 encoded. Files have size limits that can be obtained via the [`Policy`](#policy) call. The server shall strictly enforce policy limits. |

### `Metadata`

| | Type | Description |
|-|-|-|
| Digest | string | SHA256 digest of the JSON encoded payload |
| Hint | string | Hint that describes the payload |
| Payload | string | Base64 encoded metadata content where the metadata content is JSON encoded. |

### `Proposal metadata`
| | Type | Description |
|-|-|-|
| Name | string | Proposal name. |
| LinkTo | string | Censorship token of the proposal to link to (optional). |
| LinkBy | int64 | Unix timestamp of the RFP deadline (optional). |

### `Vote summary`

| | Type | Description |
|-|-|-|
| status | int | Status identifier |
| approved | bool | Has the proposal vote passed |
| type | [`VoteT`](#vote-types)| Vote type (omitempty) |
| eligibletickets | int | Total number of eligible tickets (omitempty) |
| duration | uint32 | Duration of the vote in blocks (omitempty) |
| endheight | uint64 | The chain height in which the vote will end (omitempty) |
| quorumpercentage | uint32 | Percent of eligible votes required for quorum (omitempty) |
| passpercentage | uint32 | Percent of total votes required to pass (omitempty) |
| optionsresult | array of VoteOptionResult | Option description along with the number of votes it has received (omitempty) |

### `Censorship record`

| | Type | Description |
|-|-|-|
| token | string | The token is a 32 byte random number that was assigned to identify the submitted proposal. This is the key to later retrieve the submitted proposal from the system. |
| merkle | string | Merkle root of the proposal. This is defined as the sorted digests of all files proposal files. The client should cross verify this value. |
| signature | string | Signature of byte array representations of merkle+token. The token byte array is appended to the merkle root byte array and then signed. The client should verify the signature. |

### `Login reply`

This object will be sent in the result body on a successful [`Login`](#login)
or [`Me`](#me) call.

| Parameter | Type | Description |
|-|-|-|
| isadmin | boolean | This indicates if the user has publish/censor privileges. |
| userid | string | Unique user identifier. |
| email | string | Current user email address. |
| publickey | string | Current public key. |
| paywalladdress | String | The address in which to send the transaction containing the `paywallamount`.  If the user has already paid, this field will be empty or not present. |
| paywallamount | Int64 | The amount of DCR (in atoms) to send to `paywalladdress`.  If the user has already paid, this field will be empty or not present. |
| paywalltxnotbefore | Int64 | The minimum UNIX time (in seconds) required for the block containing the transaction sent to `paywalladdress`.  If the user has already paid, this field will be empty or not present. |
| lastlogintime | int64 | The UNIX timestamp of the last login date; it will be 0 if the user has not logged in before. |
| sessionmaxage | int64 | The UNIX timestamp of the session max age. |

### `Proposal credit`
A proposal credit allows the user to submit a new proposal.  Proposal credits are a spam prevention measure.  Credits are created when a user sends a payment to a proposal paywall. The user can request proposal paywall details using the [`Proposal paywall details`](#proposal-paywall-details) endpoint.  A credit is automatically spent every time a user submits a new proposal.

| | Type | Description |
|-|-|-|
| paywallid | uint64 | The ID of the proposal paywall that created this credit. |
| price | uint64 | The price that the credit was purchased at in atoms. |
| datepurchased | int64 | A Unix timestamp of the purchase data. |
| txid | string | The txID of the Decred transaction that paid for this credit. |

## Websocket methods

### `WSHeader`
| Parameter | Type | Description | Required |
|-|-|-|-|
|Command|string|Type of JSON structure that follows the header|yes|
|ID|string|Client settable ID|no|

**WSHeader** is required as a prefix to every other command on both the client
and server side.

### `WSError`
| Parameter | Type | Description | Required |
|-|-|-|-|
|Command|string|Type of JSON structure that follows the header|no|
|ID|string|Client settable ID|no|
|Errors|array of string|All errors that occurred during execution of the failed command|yes|

**WSError** always flows from server to client.

**example**
```
{
  "command": "error",
  "id": "1"
}
{
  "command": "subscribe",
  "id": "1",
  "errors": [
    "invalid subscription pingo"
  ]
}
```

### `WSSubscribe`
| Parameter | Type | Description | Required |
|-|-|-|-|
|RPCS|array of string|Subscriptions|yes|

Current valid subscriptions are `ping`.

Sending additional `subscribe` commands will result in the old subscription
list being overwritten and thus an empty `rpcs` cancels all subscriptions.

**WSSubscribe** always flows from client to server.

**Example**
```
{
  "command": "subscribe",
  "id": "1"
}
{
  "rpcs": [
    "ping"
  ]
}
```


### `WSPing`
| Parameter | Type | Description | Required |
|-|-|-|-|
|Timestamp|int64|Server timestamp|yes|

**WSPing** always flows from server to client.

**example**
```
{
  "command": "ping"
}
{
  "timestamp": 1547653596
}
```
