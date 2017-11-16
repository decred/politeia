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
- [`Change password`](#change-password)
- [`Reset password`](#reset-password)
- [`Vetted`](#vetted)
- [`Unvetted`](#unvetted)
- [`New proposal`](#new-proposal)
- [`Proposal details`](#proposal-details)
- [`Set proposal status`](#set-proposal-status)
- [`Policy`](#policy)
- [`New comment`](#new-comment)
- [`Get comments`](#get-comments)

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

**Proposal status codes**

- [`PropStatusInvalid`](#PropStatusInvalid)
- [`PropStatusNotFound`](#PropStatusNotFound)
- [`PropStatusNotReviewed`](#PropStatusNotReviewed)
- [`PropStatusCensored`](#PropStatusCensored)
- [`PropStatusPublic`](#PropStatusPublic)

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

**Route**: `GET /`

**Params**: none

**Results**:

| | Type | Description |
|-|-|-|
| version | number | API version that is running on this server. |
| route | string | Route that should be prepended to all calls. For example, "/v1". |
| identity | string | Identity that signs various tokens to ensure server authenticity and to prevent replay attacks. |

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

**Route**: `GET /user/me`

**Params**: none

**Results**:

| | Type | Description |
|-|-|-|
| userid | string | Unique user identifier. |
| email | string | User ID. |
| isadmin | string | This indicates if the user has publish/censor privileges. |
| publickey | string | Current active public key. |

If there currently is no session the call returns `403 Forbidden`.

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
  "publickey":"5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b"
}
```

### `New user`

Create a new user on the politeiawww server.

**Route:** `POST /v1/user/new`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| email | string | Email is used as the web site user identity for a user. When a user changes email addresses the server shall maintain a mapping between the old and new address. | Yes |
| password | string | The password that the user wishes to use. This password travels in the clear in order to enable JS-less systems. The server shall never store passwords in the clear. | Yes |
| publickey | string | User ed25519 public key. | Yes |

**Results:**

| Parameter | Type | Description |
|-|-|-|
| verificationtoken | string | The verification token which is required when calling [Verify user](#verify-user). If an email server is set up, this property will be empty or nonexistent; the token will be sent to the email address sent in the request. |

This call can return one of the following error codes:

- [`ErrorStatusInvalidEmailOrPassword`](#ErrorStatusInvalidEmailOrPassword)
- [`ErrorStatusMalformedEmail`](#ErrorStatusMalformedEmail)

The email shall include a link in the following format:

```
/user/verify?email=69af376cca42cd9c@example.com&verificationtoken=fc8f660e7f4d590e27e6b11639ceeaaec2ce9bc6b0303344555ac023ab8ee55f&signature=9e4b1018913610c12496ec3e482f2fb42129197001c5d35d4f5848b77d2b5e5071f79b18bcab4f371c5b378280bb478c153b696003ac3a627c3d8a088cd5f00d
```

The call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

* **Example**

Request:

```json
{
  "email": "69af376cca42cd9c@example.com",
  "password": "69af376cca42cd9c"
  "publickey":"5203ab0bb739f3fc267ad20c945b81bcb68ff22414510c000305f4f0afb90d1b",
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
/v1/user/verify?email=abc@example.com&verificationtoken=f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde
```

Reply:

```json
{}
```

### `Me`

Return information of the current logged in user.

**Route:** `GET /v1/me`

**Params:**

N/A

**Results:**

| Parameter | Type | Description |
|-|-|-|
| isadmin | boolean | This indicates if the user has publish/censor privileges. |
| userid | string | Unique user identifier. |
| email | string | Current user email address. |
| publickey | string | Current public key. |

On failure the call shall return `403 Forbidden` and one of the following
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
  "publickey":"ec88b934fd9f334a9ed6d2e719da2bdb2061de5370ff20a38b0e1e3c9538199a"
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

**Results:**

| Parameter | Type | Description |
|-|-|-|
| isadmin | boolean | This indicates if the user has publish/censor privileges. |
| userid | string | Unique user identifier. |
| email | string | Current user email address. |
| publickey | string | Current public key. |

On failure the call shall return `403 Forbidden` and one of the following
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
  "publickey":"ec88b934fd9f334a9ed6d2e719da2bdb2061de5370ff20a38b0e1e3c9538199a"
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

**Results:** none

The reset password command is special.  It must be called **twice** with different
parameters.

For the 1st call, it should be called with only an `email` parameter. On success
it shall send an email to the address provided by `email` and return `200 OK`.

The email shall include a link in the following format:

```
/user/password/reset?email=abc@example.com&verificationtoken=f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde
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
{}
```

### `New proposal`

Submit a new proposal to the politeiawww server.
The proposal name is derived from the first line of the markdown file - index.md.

**Route:** `POST /v1/proposal/new`

**Params:**

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| files | array of [`File`](#file)s | Files are the body of the proposal. It should consist of one markdown file - named "index.md" - and up to five pictures. **Note:** all parameters within each [`File`](#file) are required. | Yes |
| signature | string | Signature of the string representation of the Merkle root of the files payload. Note that the merkle digests are calculated on the decoded payload.. | Yes |

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
  }]
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

**Route:** `GET /v1/unvetted`

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

```json
{}
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
```

### `Vetted`

Retrieve a page of vetted proposals; the number of proposals returned in the page is limited by the `proposallistpagesize` property, which is provided via [`Policy`](#policy).

**Route:** `GET /v1/vetted`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| before | String | A proposal censorship token; if provided, the page of proposals returned will end right before the proposal whose token is provided. This parameter should not be specified if `after` is set. | |
| after | String | A proposal censorship token; if provided, the page of proposals returned will begin right after the proposal whose token is provided. This parameter should not be specified if `before` is set. | |

**Results:**

| | Type | Description |
|-|-|-|
| proposals | Array of [`Proposal`](#proposal)s | An Array of unvetted proposals. |

**Example**

Request:

```json
{}
```

Reply:

```json
{
  "proposals": [{
    "name": "My Proposal",
    "status": 4,
    "timestamp": 1508296860781,
    "numcomments": 0,
    "censorshiprecord": {
      "token": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
      "merkle": "0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
      "signature": "fcc92e26b8f38b90c2887259d88ce614654f32ecd76ade1438a0def40d360e461d995c796f16a17108fad226793fd4f52ff013428eda3b39cd504ed5f1811d0d"
    }
  }]
```

### `Policy`

Retrieve server policy.  The returned values contain various maxima that the client
SHALL observe.

**Route:** `GET /v1/policy`

**Params:** none

**Results:** none

**Example**

Request:

```json
{}
```

Reply:

```json
{
  "passwordminchars": 8,
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
  "maxnamelength": 80,
  "minnamelength": 8,
  "supportedcharacters": [
     "A-z", "0-9", "&",".",":",";",",","-"," ","@","+","#"
  ]
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
| status | number | Status indicates the new status for the proposal. Valid statuses are: [PropStatusCensored](#PropStatusCensored), [PropStatusPublic](#PropStatusPublic). Status can only be changed if the current proposal status is [PropStatusNotReviewed](#PropStatusNotReviewed) | Yes |
| signature | string | Signature of token+string(status). | Yes |

**Results:** none

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusProposalNotFound`](#ErrorStatusProposalNotFound)

**Example**

Request:

```json
{
  "token": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
  "status": 4
}
```

Reply:

```json
{
  "status": 4
}
```

### `Proposal details`

Retrieve proposal and its details.

**Routes:** `POST /v1/proposals/{token}`

**Params:** none

**Results:**

| | Type | Description |
|-|-|-|
| proposal | [`Proposal`](#proposal) | The proposal with the provided token. |

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusProposalNotFound`](#ErrorStatusProposalNotFound)

**Example**

Request:

```json
{}
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
| Token | string | Censorship token | Yes |
| ParentID | string | Parent comment identifier | Yes |
| Comment | string | Comment | Yes |
| Signature | string | Signature of Token, ParentID and Comment | Yes |

**Results:**

| | Type | Description |
| - | - | - |
| CommentID | string | Server generated unique comment identifier |

On failure the call shall return `400 Bad Request` and one of the following
error codes:

- [`ErrorStatusCommentLengthExceededPolicy`](#ErrorStatusCommentLengthExceededPolicy)

**Example**

Request:

```json
{
  "token":"837f068c02b48f7f0ebe590e07d0a33bd6ce1046ba44b5f1ad0f8b4a4d0cb7f3",
  "parentid":"",
  "comment":"I dont like this prop",
  "signature":"b5ec08402e4c4c34da97bd469fc59be408a3e3978d3696ac6b31aed028d9d4acfe757bbd279f48a8ad81853f9d79416e9da0b563caa2f5a1dfb91f54f9edbf06"
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

```json
{}
```

Reply:

```json
{
  "comments":[{
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

### Proposal status codes

| Status | Value | Description |
|-|-|-|
| <a name="PropStatusInvalid">PropStatusInvalid</a>| 0 | An invalid status. This shall be considered a bug. |
| <a name="PropStatusNotFound">PropStatusNotFound</a> | 1 | The proposal was not found. |
| <a name="PropStatusNotReviewed">PropStatusNotReviewed</a> | 2 | The proposal has not been reviewed by an admin. |
| <a name="PropStatusCensored">PropStatusCensored</a> | 3 | The proposal has been censored by an admin. |
| <a name="PropStatusPublic">PropStatusPublic</a> | 4 | The proposal has been published by an admin. |

### `Proposal`

| | Type | Description |
|-|-|-|
| name | string | The name of the proposal. |
| status | number | Current status of the proposal. |
| timestamp | number | The unix time of the last update of the proposal. |
| censorshiprecord | [`censorshiprecord`](#censorship-record) | The censorship record that was created when the proposal was submitted. |
| files | array of [`File`](#file)s | This property will only be populated for the [`Proposal details`](#proposal-details) call. |
| numcomments | Number | Number of comments. This will only be polulated for the [`Vetted`](#vetted) call. |

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
