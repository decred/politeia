# politeiawww API Specification

# v1

This document describes the REST API provided by a `politeiawww` server.  The
`politeiawww` server is the web server backend and it interacts with a JSON
REST API.  This document also describes websockets for server side
notifications.  It does not render HTML.

**Methods**

- [`Version`](#version)
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
- [`New comment`](#new-comment)
- [`Get comments`](#get-comments)
- [`Like comment`](#like-comment)
- [`Censor comment`](#censor-comment)
- [`Policy`](#policy)

***Proposal Routes***
- [`Vetted`](#vetted)
- [`Unvetted`](#unvetted)
- [`User proposals`](#user-proposals)
- [`Proposal paywall details`](#proposal-paywall-details)
- [`User proposal credits`](#user-proposal-credits)
- [`Verify user payment`](#verify-user-payment)
- [`New proposal`](#new-proposal)
- [`Edit Proposal`](#edit-proposal)
- [`Proposal details`](#proposal-details)
- [`Set proposal status`](#set-proposal-status)
- [`Authorize vote`](#authorize-vote)
- [`Start vote`](#start-vote)
- [`Active votes`](#active-votes)
- [`Cast votes`](#cast-votes)
- [`Proposal vote status`](#proposal-vote-status)
- [`Proposals vote status`](#proposals-vote-status)
- [`Vote results`](#vote-results)
- [`User Comments votes`](#user-comments-votes)
- [`Proposals Stats`](#proposals-stats)


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
- [`ErrorStatusCannotCommentOnProp`](#ErrorStatusCannotCommentOnProp)
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
- [`ErrorStatusMalformedName`](#ErrorStatusMalformedName)
- [`ErrorStatusMalformedLocation`](#ErrorStatusMalformedLocation)
- [`ErrorStatusInvoiceNotFound`](#ErrorStatusInvoiceNotFound)
- [`ErrorStatusInvalidMonthYearRequest`](#ErrorStatusInvalidMonthYearRequest)
- [`ErrorStatusMalformedInvoiceFile`](#ErrorStatusMalformedInvoiceFile)
- [`ErrorStatusInvalidInvoiceStatusTransition`](#ErrorStatusInvalidInvoiceStatusTransition)
- [`ErrorStatusReasonNotProvided`](#ErrorStatusReasonNotProvided)
- [`ErrorStatusInvoiceDuplicate`](#ErrorStatusInvoiceDuplicate)
- [`ErrorStatusInvalidPaymentAddress`](#ErrorStatusInvalidPaymentAddress)
- [`ErrorStatusMalformedLineItem`](#ErrorStatusMalformedLineItem)
- [`ErrorStatusInvoiceMissingName`](#ErrorStatusInvoiceMissingName)
- [`ErrorStatusInvoiceMissingLocation`](#ErrorStatusInvoiceMissingLocation)
- [`ErrorStatusInvoiceMissingContact`](#ErrorStatusInvoiceMissingContact)
- [`ErrorStatusInvoiceMissingRate`](#ErrorStatusInvoiceMissingRate)
- [`ErrorStatusInvoiceInvalidRate`](#ErrorStatusInvoiceInvalidRate)
- [`ErrorStatusInvoiceMalformedContact`](#ErrorStatusInvoiceMalformedContact)
- [`ErrorStatusMalformedProposalToken`](#ErrorStatusMalformedProposalToken)
- [`ErrorStatusMalformedDomain`](#ErrorStatusMalformedDomain)
- [`ErrorStatusMalformedSubdomain`](#ErrorStatusMalformedSubdomain)
- [`ErrorStatusMalformedDescription`](#ErrorStatusMalformedDescription) 
- [`ErrorStatusWrongInvoiceStatus`](#ErrorStatusWrongInvoiceStatus) 
- [`ErrorStatusInvoiceRequireLineItems`](#ErrorStatusInvoiceRequireLineItems)
- [`ErrorStatusInvalidInvoiceMonthYear`](#ErrorStatusInvalidInvoiceMonthYear)
- [`ErrorStatusMultipleInvoiceMonthYear`](#ErrorStatusMultipleInvoiceMonthYear)
- [`ErrorStatusInvalidLineItemType`](#ErrorStatusInvalidLineItemType) 
- [`ErrorStatusInvalidLaborExpense`](#ErrorStatusInvalidLaborExpense)
- [`ErrorStatusNoProposalChanges`](#ErrorStatusNoProposalChanges)
- [`ErrorStatusDuplicatePaymentAddress`](#ErrorStatusDuplicatePaymentAddress)

**Proposal status codes**

- [`PropStatusInvalid`](#PropStatusInvalid)
- [`PropStatusNotFound`](#PropStatusNotFound)
- [`PropStatusNotReviewed`](#PropStatusNotReviewed)
- [`PropStatusCensored`](#PropStatusCensored)
- [`PropStatusPublic`](#PropStatusPublic)
- [`PropStatusAbandoned`](#PropStatusAbandoned)

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
- [`ErrorStatusInvalidPassword`](#ErrorStatusInvalidPassword)
- [`ErrorStatusUserLocked`](#ErrorStatusUserLocked)
- [`ErrorStatusUserDeactivated`](#ErrorStatusUserDeactivated)
- [`ErrorStatusEmailNotVerified`](#ErrorStatusEmailNotVerified)

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

Returns details about a user given its id. This call requires admin privileges.

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

```json
{
  "user": {
    "id": "0",
    "email": "6b87b6ebb0c80cb7@example.com",
    "username": "6b87b6ebb0c80cb7",
    "isadmin": false,
    "newuserpaywalladdress": "Tsgs7qb1Gnc43D9EY3xx9ou8Lbo8rB7me6M",
    "newuserpaywallamount": 10000000,
    "newuserpaywalltxnotbefore": 1528821554,
    "newuserpaywalltx": "",
    "newuserpaywallpollexpiry": 1528821554,
    "newuserverificationtoken": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
    "newuserverificationexpiry": 1528821554,
    "updatekeyverificationtoken": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
    "updatekeyverificationexpiry": 1528821554,
    "numofproposals": 0,
    "resetpasswordverificationtoken": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
    "resetpasswordverificationexpiry": 1528821554,
    "identities": [{
      "pubkey": "5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b",
      "isactive": true
    }],
    "comments": []
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
The proposal name is derived from the first line of the markdown file - index.md.

**Route:** `POST /v1/proposals/new`

**Params:**

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| files | array of [`File`](#file)s | Files are the body of the proposal. It should consist of one markdown file - named "index.md" - and up to five pictures. **Note:** all parameters within each [`File`](#file) are required. | Yes |
| signature | string | Signature of the string representation of the Merkle root of the files payload. Note that the merkle digests are calculated on the decoded payload.. | Yes |
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
The proposal name is derived from the first line of the markdown file - index.md.

Note that updating public proposals will generate a new record version. While
updating an unvetted record will change the record but it will not generate
a new version.

The example shown below is for a public proposal where the proposal version is increased
by one after the update.

**Route:** `POST /v1/proposals/edit`

**Params:**

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| files | array of [`File`](#file)s | Files are the body of the proposal. It should consist of one markdown file - named "index.md" - and up to five pictures. **Note:** all parameters within each [`File`](#file) are required. | Yes |
| signature | string | Signature of the string representation of the Merkle root of the files payload. Note that the merkle digests are calculated on the decoded payload.. | Yes |
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


### `Unvetted`

Retrieve a page of unvetted proposals; the number of proposals returned in the
page is limited by the `ProposalListPageSize` property, which is provided via
[`Policy`](#policy).  This call requires admin privileges.

**Route:** `GET /v1/proposals/unvetted`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| before | String | A proposal censorship token; if provided, the page of proposals returned will end right before the proposal whose token is provided, when sorted in reverse chronological order. This parameter should not be specified if `after` is set. | |
| after | String | A proposal censorship token; if provided, the page of proposals returned will begin right after the proposal whose token is provided, when sorted in reverse chronological order. This parameter should not be specified if `before` is set. | |

**Results:**

| | Type | Description |
|-|-|-|
| proposals | array of [`Proposal`](#proposal)s | An Array of unvetted proposals. |

If the caller is not privileged the unvetted call returns `403 Forbidden`.

**Example**

Request:

The request params should be provided within the URL:

```
/v1/proposals/unvetted?after=f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde
```

Reply:

```json
{
  "proposals": [{
      "name": "My Proposal",
      "status": 2,
      "timestamp": 1508296860781,
      "publishedat": 0,
      "censoredat": 0,
      "abandonedat": 0,
      "censorshiprecord": {
        "token": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
        "merkle": "0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
        "signature": "fcc92e26b8f38b90c2887259d88ce614654f32ecd76ade1438a0def40d360e461d995c796f16a17108fad226793fd4f52ff013428eda3b39cd504ed5f1811d0d"
      }
    }
  ]
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

Retrieve server policy.  The returned values contain various maxima that the client
SHALL observe.

**Route:** `GET /v1/policy`

**Params:** none

**Results:**

| | Type | Description |
|-|-|-|
| minpasswordlength | integer | minimum number of characters accepted for user passwords |
| minusernamelength | integer | minimum number of characters accepted for username |
| maxusernamelength | integer | maximum number of characters accepted for username |
| usernamesupportedchars | array of strings | the regular expression of a valid username |
| proposallistpagesize | integer | maximum number of proposals returned for the routes that return lists of proposals |
| userlistpagesize | integer | maximum number of users returned for the routes that return lists of users |
| maximages | integer | maximum number of images accepted when creating a new proposal |
| maximagesize | integer | maximum image file size (in bytes) accepted when creating a new proposal |
| maxmds | integer | maximum number of markdown files accepted when creating a new proposal |
| maxmdsize | integer | maximum markdown file size (in bytes) accepted when creating a new proposal |
| validmimetypes | array of strings | list of all acceptable MIME types that can be communicated between client and server. |
| maxproposalnamelength | integer | max length of a proposal name |
| minproposalnamelength | integer | min length of a proposal name |
| proposalnamesupportedchars | array of strings | the regular expression of a valid proposal name |
| maxcommentlength | integer | maximum number of characters accepted for comments |
| backendpublickey | string |  |
| maxnamelength | integer | maximum contractor name length (cmswww)
| minnamelength | integer | mininum contractor name length (cmswww)
| maxlocationlength | integer | maximum contractor location length (cmswww)
| minlocationlength | integer | minimum contractor location length (cmswww)
| invoicecommentchar | char | character for comments on invoices (cmswww)
| invoicefielddelimiterchar | char | character for invoice csv field separation (cmswww)
| invoicelineitemcount | integer | expected count for line item fields (cmswww)


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
  "proposalnamesupportedchars": [
     "A-z", "0-9", "&", ".", ":", ";", ",", "-", " ", "@", "+", "#"
  ],
  "maxcommentlength": 8000,
  "backendpublickey": "",
  "minproposalnamelength": 8,
  "maxproposalnamelength": 80
}
```

### `Set proposal status`

Set status of proposal to `PropStatusPublic`, `PropStatusCensored` or
`PropStatusAbandoned`.  This call requires admin privileges.

**Route:** `POST /v1/proposals/{token}/status`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| token | string | Token is the unique censorship token that identifies a specific proposal. | Yes |
| proposalstatus | number | Status indicates the new status for the proposal. Valid statuses are: [PropStatusCensored](#PropStatusCensored), [PropStatusPublic](#PropStatusPublic), [PropStatusAbandoned](#PropStatusAbandoned). | Yes |
| signature | string | Signature of token+string(status). | Yes |
| publickey | string | Public key from the client side, sent to politeiawww for verification | Yes |

**Results:**

| Parameter | Type | Description |
|-|-|-|
| proposal | [`Proposal`](#proposal) | an entire proposal and it's content |

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusNoPublicKey`](#ErrorStatusNoPublicKey)
- [`ErrorStatusInvalidSigningKey`](#ErrorStatusInvalidSigningKey)
- [`ErrorStatusInvalidSignature`](#ErrorStatusInvalidSignature)
- [`ErrorStatusChangeMessageCannotBeBlank`](#ErrorStatusChangeMessageCannotBeBlank)
- [`ErrorStatusProposalNotFound`](#ErrorStatusProposalNotFound)
- [`ErrorStatusReviewerAdminEqualsAuthor`](#ErrorStatusReviewerAdminEqualsAuthor)
- [`ErrorStatusInvalidPropStatusTransition`](#ErrorStatusInvalidPropStatusTransition)
- [`ErrorStatusWrongVoteStatus`](#ErrorStatusWrongVoteStatus)

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

Retrieve proposal and its details.

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
| resultvotes | int64 | Vote score |

On failure the call shall return `400 Bad Request` and one of the following
error codes:

- [`ErrorStatusCommentLengthExceededPolicy`](#ErrorStatusCommentLengthExceededPolicy)
- [`ErrorStatusUserNotPaid`](#ErrorStatusUserNotPaid)

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
  "totalvotes": 0,
  "resultvotes": 0
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
    "resultvotes": 3
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
    "resultvotes": 3
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
    "resultvotes": 3
  }],
  "accesstime": 1543539276
}
```

### `Like comment`

Allows a user to up or down vote a comment

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
| result | int64 | Vote score |
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
  "result": 3,
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
- [`ErrorStatusInvalidSignature`](#ErrorStatusInvalidSignature)
- [`ErrorStatusCensorReasonCannotBeBlank`](#ErrorStatusCensorReasonCannotBeBlank)
- [`ErrorStatusCannotCensorComment`](#ErrorStatusCannotCensorComment)

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


### `Start vote`

Call a vote on the given proposal.

Note that the webserver does not interpret the plugin structures. These are
forwarded as-is to the politeia daemon.

**Route:** `POST /v1/proposals/startvote`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| publickey | string | Public key used to sign the vote | Yes |
| vote | Vote | Vote details | Yes |
| signature | string | Signature of the Vote | Yes |

**Results (StartVoteReply):**

| | Type | Description |
| - | - | - |
| startblockheight | string | String encoded start block height of the vote |
| startblockhash | string | String encoded start block hash of the vote |
| endheight | string | String encoded final block height of the vote |
| eligibletickets | array of string | String encoded tickets that are eligible to vote |

**Vote:**

| | Type | Description |
| - | - | - |
| token | string | Censorship token |
| mask | uint64 | Mask for valid vote bits |
| duration | uint32 | Duration of the vote in blocks |
| options | array of VoteOption | Vote options |

**VoteOption:**

| | Type | Description |
| - | - | - |
| Id | string | Single unique word that identifies this option, e.g. "yes" |
| Description | string | Human readable description of this option |
| Bits | uint64 | Bits that make up this choice, e.g. 0x01 |

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusNoPublicKey`](#ErrorStatusNoPublicKey)
- [`ErrorStatusInvalidSigningKey`](#ErrorStatusInvalidSigningKey)
- [`ErrorStatusInvalidSignature`](#ErrorStatusInvalidSignature)
- [`ErrorStatusInvalidPropVoteBits`](#ErrorStatusInvalidPropVoteBits)
- [`ErrorStatusInvalidPropVoteParams`](#ErrorStatusInvalidPropVoteParams)
- [`ErrorStatusProposalNotFound`](#ErrorStatusProposalNotFound)
- [`ErrorStatusWrongStatus`](#ErrorStatusWrongStatus)
- [`ErrorStatusVoteNotAuthorized`](#ErrorStatusVoteNotAuthorized)
- [`ErrorStatusWrongVoteStatus`](#ErrorStatusWrongVoteStatus)

**Example**

Request:

``` json
{
  "publickey": "d64d80c36441255e41fc1e7b6cd30259ff9a2b1276c32c7de1b7a832dff7f2c6",
  "vote": {
    "token": "127ea26cf994dabc27e115da0eb90a5657590e2ccc4e7c23c7f80c6fe4afaa59",
    "mask": 3,
    "duration": 2016,
    "Options": [{
      "id": "no",
      "description": "Don't approve proposal",
      "bits": 1
    },{
      "id": "yes",
      "description": "Approve proposal",
      "bits": 2
    }]
  },
  "signature": "5a40d699cdfe5ee31472ec252982e60265a345cd58e4a07b183cf06447b3942d06981e1bfaf8430195109d51428458449446fbfa1d7059aebedc4df769ddb300"
}
```

Reply:

```json
{
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
```

Note: eligibletickets is abbreviated for readability.

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

Retrieve vote results for a specified censorship token.

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

Returns the vote status for a single public proposal

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

Returns the vote status of all public proposals

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

### `Proposals Stats`

Retrieve the counting of proposals aggrouped by each proposal status.

**Route:** `GET v1/proposals/stats`

**Params:** none

**Results:**

| | Type | Description |
| - | - | - |
| numofcensored | int | Counting number of censored proposals. |
| numofunvetted | int | Counting number of unvetted proposals. |
| numofunvettedchanges | int | Counting number of proposals with unvetted changes |
| numofpublic | int | Counting number of public proposals. |

**Example:**
Request:
Path: `v1/proposals/stats`

Reply:

```json
{
  "numofcensored":1,
  "numofunvetted":0,
  "numofunvettedchanges":1,
  "numofpublic":3
}
```

### Error codes

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
| <a name="ErrorStatusCannotCommentOnProp">ErrorStatusCannotCommentOnProp</a> | 43 | Cannot comment on proposal. |
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
| <a name="ErrorStatusNoProposalChanges">ErrorStatusNoProposalChanges</a> | 88 | No changes found in proposal. |


### Proposal status codes

| Status | Value | Description |
|-|-|-|
| <a name="PropStatusInvalid">PropStatusInvalid</a>| 0 | An invalid status. This shall be considered a bug. |
| <a name="PropStatusNotFound">PropStatusNotFound</a> | 1 | The proposal was not found. |
| <a name="PropStatusNotReviewed">PropStatusNotReviewed</a> | 2 | The proposal has not been reviewed by an admin. |
| <a name="PropStatusCensored">PropStatusCensored</a> | 3 | The proposal has been censored by an admin. |
| <a name="PropStatusPublic">PropStatusPublic</a> | 4 | The proposal has been published by an admin. |
| <a name="PropStatusUnreviewedChanges">PropStatusUnreviewedChanges</a> | 5 | The proposal has not been rewieved by an admin yet and has been edited by the author. |
| <a name="PropStatusAbandoned">PropStatusAbandoned</a> | 6 | The proposal is public and has been deemed abandoned by an admin. |

### User edit actions

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

### Email notifications

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
| publickey | string | The public key of the user who created the proposal. |
| signature | string | The signature of the merkle root, signed by the user who created the proposal. |
| version | string | The proposal version. |
| censorshiprecord | [`censorshiprecord`](#censorship-record) | The censorship record that was created when the proposal was submitted. |
| files | array of [`File`](#file)s | This property will only be populated for the [`Proposal details`](#proposal-details) call. |
| numcomments | number | The number of comments on the proposal. This should be ignored for proposals which are not public. |
| statatuschangemessage | Message associated to the status change. |
| pubishedat | The timestamp of when the proposal has been published. If the proposals has not been pubished, this field will not be present. |
| censoredat | The timestamp of when the proposal has been censored. If the proposals has not been censored, this field will not be present. |
| abandonedat | The timestamp of when the proposal has been abandoned. If the proposals has not been abandoned, this field will not be present. |
 
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
