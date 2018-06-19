# politeiawww API Specification

# v1

This document describes the REST API provided by a `politeiawww` server.  The
`politeiawww` server is the web server backend and it interacts with a JSON REST
API.  It does not render HTML.

**Methods**

- [`Version`](#version)
- [`New user`](#new-user)
- [`Verify user`](#verify-user)
- [`Me`](#me)
- [`Login`](#login)
- [`Logout`](#logout)
- [`Verify user payment`](#verify-user-payment)
- [`Update user key`](#update-user-key)
- [`Verify update user key`](#verify-update-user-key)
- [`Change username`](#change-username)
- [`Change password`](#change-password)
- [`Reset password`](#reset-password)
- [`Vetted`](#vetted)
- [`Unvetted`](#unvetted)
- [`User proposals`](#user-proposals)
- [`New proposal`](#new-proposal)
- [`Proposal details`](#proposal-details)
- [`Set proposal status`](#set-proposal-status)
- [`Policy`](#policy)
- [`New comment`](#new-comment)
- [`Get comments`](#get-comments)
- [`Start vote`](#start-vote)
- [`Active votes`](#active-votes)
- [`Cast votes`](#cast-votes)
- [`Proposal votes`](#proposal-votes)
- [`Usernames by id`](#usernames-by-id)
- [`User Comments votes`](#user-comments-votes)

**Error status codes**

- [`ErrorStatusInvalid`](#ErrorStatusInvalid)
- [`ErrorStatusInvalidEmailOrPassword`](#ErrorStatusInvalidEmailOrPassword)
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
- [`ErrorStatusInvalidProposalName`](#ErrorStatusInvalidProposalName)
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


**Proposal status codes**

- [`PropStatusInvalid`](#PropStatusInvalid)
- [`PropStatusNotFound`](#PropStatusNotFound)
- [`PropStatusNotReviewed`](#PropStatusNotReviewed)
- [`PropStatusCensored`](#PropStatusCensored)
- [`PropStatusPublic`](#PropStatusPublic)
- [`PropStatusLocked`](#PropStatusLocked)

## HTTP status codes and errors

All methods, unless otherwise specified, shall return `200 OK` when successful,
`400 Bad Request` when an error has occurred due to user input, or `500 Internal Server Error`
when an unexpected server error has occurred. The format of errors is as follows:

**`4xx` errors**

| | Type | Description |
|-|-|-|
| errorcode | number | One of the [error codes](#error-codes) |
| errorcontext | Array of Strings | This array of strings is used to provide additional information for certain errors; see the documentation for specific error codes. |

**`5xx` errors**

| | Type | Description |
|-|-|-|
| errorcode | number | An error code that can be used to track down the internal server error that occurred; it should be reported to Politeia administrators. |

## Methods

### `Version`

Obtain version, route information and signing identity from server.  This call
shall **ALWAYS** be the first contact with the server.  This is done in order
to get the CSRF token for the session and to ensure API compatability.

**Route**: `GET /` and `GET /version`

**Params**: none

**Results**:

| | Type | Description |
|-|-|-|
| version | number | API version that is running on this server. |
| route | string | Route that should be prepended to all calls. For example, "/v1". |
| pubkey | string | The public key for the corresponding private key that signs various tokens to ensure server authenticity and to prevent replay attacks. |
| testnet | boolean | Value to inform either its running on testnet or not |

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
  "identity": "99e748e13d7ecf70ef6b5afa376d692cd7cb4dbb3d26fa83f417d29e44c6bb6c"
}
```

### `Me`

Return pertinent user information of the current logged in user.

**Route**: `GET /v1/user/me`

**Params**: none

**Results**: See the [`Login reply`](#login-reply).

On failure the call shall return `403 Forbidden` and one of the following
error codes:
- [`ErrorStatusInvalidEmailOrPassword`](#ErrorStatusInvalidEmailOrPassword)

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
  "paywallamount":"10000000",
  "paywalltxnotbefore":"1528821554"
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
| paywalladdress | String | The address in which to send the transaction containing the `paywallamount`. |
| paywallamount | Int64 | The amount of DCR (in atoms) to send to `paywalladdress`. |
| paywalltxnotbefore | Int64 | The minimum UNIX time (in seconds) required for the block containing the transaction sent to `paywalladdress`. |
| verificationtoken | String | The verification token which is required when calling [Verify user](#verify-user). If an email server is set up, this property will be empty or nonexistent; the token will be sent to the email address sent in the request.|

This call can return one of the following error codes:

- [`ErrorStatusMalformedEmail`](#ErrorStatusMalformedEmail)
- [`ErrorStatusMalformedUsername`](#ErrorStatusMalformedUsername)
- [`ErrorStatusDuplicateUsername`](#ErrorStatusDuplicateUsername)
- [`ErrorStatusMalformedPassword`](#ErrorStatusMalformedPassword)

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
- [`ErrorStatusInvalidEmailOrPassword`](#ErrorStatusInvalidEmailOrPassword)

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
| haspaid | boolean | Whether or not a transaction on the blockchain that was sent to the `paywalladdress` (which is provided on [`New user`](#new-user) and the [`Login reply`](#login-reply) could be found and verified. |

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
  "haspaid": true
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
| verificationtoken | String | The verification token which is required when calling [Verify update user key](#verify-update-user-key). If an email server is set up, this property will be empty or nonexistent; the token will be sent to the email address sent in the request. |

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
- [`ErrorStatusInvalidEmailOrPassword`](#ErrorStatusInvalidEmailOrPassword)
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
- [`ErrorStatusInvalidEmailOrPassword`](#ErrorStatusInvalidEmailOrPassword)
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

### `Unvetted`

Retrieve a page of unvetted proposals; the number of proposals returned in the page is limited by the `proposallistpagesize` property, which is provided via [`Policy`](#policy).  This call requires admin privileges.

**Route:** `GET /v1/proposals/unvetted`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| before | String | A proposal censorship token; if provided, the page of proposals returned will end right before the proposal whose token is provided. This parameter should not be specified if `after` is set. | |
| after | String | A proposal censorship token; if provided, the page of proposals returned will begin right after the proposal whose token is provided. This parameter should not be specified if `before` is set. | |

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

Retrieve a page of vetted proposals; the number of proposals returned in the page is limited by the `proposallistpagesize` property, which is provided via [`Policy`](#policy).

**Route:** `GET /v1/proposals/vetted`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| before | String | A proposal censorship token; if provided, the page of proposals returned will end right before the proposal whose token is provided. This parameter should not be specified if `after` is set. | |
| after | String | A proposal censorship token; if provided, the page of proposals returned will begin right after the proposal whose token is provided. This parameter should not be specified if `before` is set. | |

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
    "censorshiprecord": {
      "token": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
      "merkle": "0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
      "signature": "fcc92e26b8f38b90c2887259d88ce614654f32ecd76ade1438a0def40d360e461d995c796f16a17108fad226793fd4f52ff013428eda3b39cd504ed5f1811d0d"
    }
  }]
}
```

### `User proposals`

Retrieve a page of proposals submitted by the given user; the number of proposals returned in the page is limited by the `proposallistpagesize` property, which is provided via [`Policy`](#policy).

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
| proposals | array of [`Proposal`](#proposal)s | An Array of proposals submitted by the user. |

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
  }]
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
    "image/svg+xml",
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

Set status of proposal to `PropStatusPublic` or `PropStatusCensored`.  This
call requires admin privileges.

**Route:** `POST /v1/proposals/{token}/status`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| token | string | Token is the unique censorship token that identifies a specific proposal. | Yes |
| proposalstatus | number | Status indicates the new status for the proposal. Valid statuses are: [PropStatusCensored](#PropStatusCensored), [PropStatusPublic](#PropStatusPublic). Status can only be changed if the current proposal status is [PropStatusNotReviewed](#PropStatusNotReviewed) | Yes |
| signature | string | Signature of token+string(status). | Yes |
| publickey | string | Public key from the client side, sent to politeiawww for verification | Yes |

**Results:**

| Parameter | Type | Description |
|-|-|-|-|
| proposal | [`Proposal`](#proposal) | an entire proposal and it's content |

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusProposalNotFound`](#ErrorStatusProposalNotFound)

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
      "status": 3,
      "timestamp": 1508146426,
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

### `Proposal details`

Retrieve proposal and its details.

**Routes:** `GET /v1/proposals/{token}`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| token | string | Token is the unique censorship token that identifies a specific proposal. | Yes |

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
/v1/proposals/f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde
```

Reply:

```json
{
  "proposal": {
    "name": "My Proposal",
    "status": 3,
    "timestamp": 1508146426,
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
| commentid | string | Server generated unique comment identifier |

On failure the call shall return `400 Bad Request` and one of the following
error codes:

- [`ErrorStatusCommentLengthExceededPolicy`](#ErrorStatusCommentLengthExceededPolicy)
- [`ErrorStatusUserNotPaid`](#ErrorStatusUserNotPaid)

**Example**

Request:

```json
{
  "token":"837f068c02b48f7f0ebe590e07d0a33bd6ce1046ba44b5f1ad0f8b4a4d0cb7f3",
  "parentid":"",
  "comment":"I dont like this prop",
  "signature":"b5ec08402e4c4c34da97bd469fc59be408a3e3978d3696ac6b31aed028d9d4acfe757bbd279f48a8ad81853f9d79416e9da0b563caa2f5a1dfb91f54f9edbf06",
  "publickey":"f5519b6fdee08be45d47d5dd794e81303688a8798012d8983ba3f15af70a747c"
}
```

Reply:

```json
{
  "commentid": "103"
}
```

### `Get comments`

Retrieve all comments for given proposal.  Not that the comments are not
sorted.

**Route:** `GET /v1/proposals/{token}/comments`

**Params:**

**Results:**

| | Type | Description |
| - | - | - |
| Comments | Comment | Unsorted array of all comments |

**Comment:**

| | Type | Description |
| - | - | - |
| UserID | string | Unique user identifier |
| Timestamp | int64 | UNIX time when comment was accepted |
| CommentID | string | Unique comment identifier |
| ParentID | string | Parent comment identifier |
| Token | string | Censorship token |
| Comment | string | Comment text |

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
    "commentid":"56",
    "userid":"4",
    "parentid":"0",
    "timestamp":1509990301,
    "token":"86221ddae6594b43a19e4c76250c0a8833ecd3b7a9880fb5d2a901970de9ff0e",
    "comment":"I dont like this prop"
  },{
    "commentid":"57",
    "userid":"4",
    "parentid":"56",
    "timestamp":1509990301,
    "token":"86221ddae6594b43a19e4c76250c0a8833ecd3b7a9880fb5d2a901970de9ff0e",
    "comment":"you are right!"
  },{
    "commentid":"58",
    "userid":"4",
    "parentid":"56",
    "timestamp":1509990301,
    "token":"86221ddae6594b43a19e4c76250c0a8833ecd3b7a9880fb5d2a901970de9ff0e",
    "comment":"you are crazy!"
  }]
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
| PublicKey | string | Public key used to sign the vote | Yes |
| Vote | decredplugin.Vote | Decred plugin vote | Yes |
| Signature | string | Signature of the Vote | Yes |

**Results:**

| | Type | Description |
| - | - | - |
| VoteDetails | decredplugin.StartVoteReply | Plugin reply |

**decred.Vote:**

| | Type | Description |
| - | - | - |
| Token | string | Censorship token |
| Mask | uint64 | Mask for valid vote bits |
| Duration | uint32 | Duration of the vote in blocks |
| Options | array of decredplugin.VoteOption | Vote details |

**decred.VoteOption:**

| | Type | Description |
| - | - | - |
| Id | string | Single unique word that identifies this option, e.g. "yes" |
| Description | string | Human readable description of this option |
| Bits | uint64 | Bits that make up this choice, e.g. 0x01 |

**decred.StartVoteReply:**

| | Type | Description |
| - | - | - |
| StartBlockHeight | string | String encoded start block height of the vote |
| StartBlockHash | string | String encoded start block hash of the vote |
| EndHeight | string | String encoded final block height of the vote |
| EligibleTickets | array of string | String encoded tickets that are eligible to vote |

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
  "votedetails": {
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
| Votes | array of ProposalVoteTuple | All current active votes |

**ProposalVoteTuple:**

| | Type | Description |
| - | - | - |
| Proposal | ProposalRecord | Proposal record |
| Vote | decredplugin.Vote | Vote bits, mask etc |
| VoteDetails |decredplugin.StartVoteReply | Vote details (eligible tickets, start block etc |

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
| Votes | array of decredplugin.CastVote | All votes | Yes |

**decredplugin.CastVote:**

| | Type | Description |
| - | - | - |
| Token | string | Censorship token |
| Ticket | string | Ticket hash |
| VoteBit | string | String encoded vote bit |
| Signature | string | signature of Token+Ticket+VoteBit |

**Results:**

| | Type | Description |
| - | - | - |
| Receipts | array of decredplugin.CastVoteReply  | Receipts for all cast votes. This appears in the same order and index as the votes that went in. |

**decredplugin.CastVoteReply:**

| | Type | Description |
| - | - | - |
| ClientSignature | string | Signature that was sent in via decredplugin.CastVote |
| Signature | string | Signature of ClientSignature |
| Error | string | Error, "" if there was no error |

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

### `Proposal votes`

Retrieve vote results for a specified censorship token.

Note that the webserver does not interpret the plugin structures. These are
forwarded as-is to the politeia daemon.

**Route:** `POST /v1/proposals/voteresults`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| Vote | array of decredplugin.VoteResults | Vote to recall | Yes |

**decredplugin.VoteResults:**

| | Type | Description |
| - | - | - |
| Token | string | Censorship token |

**Results:**

| | Type | Description |
| - | - | - |
| Vote | decredplugin.Vote  | Vote details |
| CastVotes | array of decredplugin.CastVote  | Vote results |

**Example**

Request:

``` json
{
  "vote": {
    "token":"642eb2f3798090b3234d8787aaba046f1f4409436d40994643213b63cb3f41da"
  }
}
```

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
  }]
}
```

### `Usernames by id`

Retrieve usernames given an array of user ids.

**Route:** `POST /v1/usernames`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| userids | array of strings | User ids | Yes |

**Results:**

| | Type | Description |
|-|-|-|
| usernames | array of strings  | Array of usernames, in the same order of the provided user ids |

**Example**

Request:

``` json
{
  "userids": ["0"]
}
```

Reply:

```json
{
  "usernames": ["foobar"]
}
```

### `User Comments Votes`

Retrieve the comment votes for the current logged in user given a proposal token

**Route:** `GET v1/user/proposals/{token}/commentsvotes`

**Params:** none

**Results:**

| | Type | Description |
| - | - | - |
| commentsvotes | array of CommentVote | Votes issued by the current user |

**CommentVote:**

| | Type | Description |
| - | - | - |
| action | string | Up or downvote (1, -1) |
| commentid | string | Comment ID |
| token | string | Proposal censorship token |

**Example:**

Request: 
Path: `v1/user/proposals/8a11057fb910564a7d2506430505c3991f59e35f8a7757b8000a032505b254d8/commentsvotes`

Reply:
```json
  {
    "commentsvotes":
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

### Error codes

| Status | Value | Description |
|-|-|-|
| <a name="ErrorStatusInvalid">ErrorStatusInvalid</a> | 0 | The operation returned an invalid status. This shall be considered a bug. |
| <a name="ErrorStatusInvalidEmailOrPassword">ErrorStatusInvalidEmailOrPassword</a> | 1 | Either the user name or password was invalid. |
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
| <a name="ErrorStatusInvalidProposalName">ErrorStatusInvalidProposalName</a> | 15 | The proposal's name was invalid. |
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
| <a name="ErrorStatusDuplicateUsername">ErrorStatusDuplicateUsername</a> | 33 | The provided username was a duplicate of another username. |
| <a name="ErrorStatusVerificationTokenUnexpired">ErrorStatusVerificationTokenUnexpired</a> | 34 | A verification token has already been generated and hasn't expired yet. |
| <a name="ErrorStatusCannotVerifyPayment">ErrorStatusCannotVerifyPayment</a> | 35 | The server cannot verify the payment at this time, please try again later. |


### Proposal status codes

| Status | Value | Description |
|-|-|-|
| <a name="PropStatusInvalid">PropStatusInvalid</a>| 0 | An invalid status. This shall be considered a bug. |
| <a name="PropStatusNotFound">PropStatusNotFound</a> | 1 | The proposal was not found. |
| <a name="PropStatusNotReviewed">PropStatusNotReviewed</a> | 2 | The proposal has not been reviewed by an admin. |
| <a name="PropStatusCensored">PropStatusCensored</a> | 3 | The proposal has been censored by an admin. |
| <a name="PropStatusPublic">PropStatusPublic</a> | 4 | The proposal has been published by an admin. |
| <a name="PropStatusLocked">PropStatusLocked</a> | 6 | The proposal has been locked by an admin. |

### `Proposal`

| | Type | Description |
|-|-|-|
| name | string | The name of the proposal. |
| status | number | Current status of the proposal. |
| timestamp | number | The unix time of the last update of the proposal. |
| userid | string | The ID of the user who created the proposal. |
| publickey | string | The public key of the user who created the proposal. |
| signature | string | The signature of the merkle root, signed by the user who created the proposal. |
| censorshiprecord | [`censorshiprecord`](#censorship-record) | The censorship record that was created when the proposal was submitted. |
| files | array of [`File`](#file)s | This property will only be populated for the [`Proposal details`](#proposal-details) call. |
| numcomments | number | The number of comments on the proposal. This should be ignored for proposals which are not public. |

### `File`

| | Type | Description |
|-|-|-|
| name | string | Name is the suggested filename. There should be no filenames that are overlapping and the name shall be validated before being used. |
| mime | string | MIME type of the payload. Currently the system only supports md and png/svg files. The server shall reject invalid MIME types. |
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
