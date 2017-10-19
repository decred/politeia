# politeiawww API Specification

## V1

This document describes the REST API provided by a `politeiawww` server.  The
`politeiawww` server is the web server backend and it interacts with a JSON REST
API.  It does not render HTML.

**Methods**

- [`Version`](#version)
- [`New user`](#new-user)
- [`Verify user`](#verify-user)
- [`Login`](#login)
- [`Logout`](#logout)
- [`Vetted`](#vetted)
- [`Unvetted`](#unvetted)
- [`New proposal`](#new-proposal)
- [`Proposal details`](#proposal-details)
- [`Set proposal status`](#set-proposal-status)
- [`Policy`](#policy)

**Status codes**

- [`StatusInvalid`](#StatusInvalid)
- [`StatusSuccess`](#StatusSuccess)
- [`StatusInvalidEmailOrPassword`](#StatusInvalidEmailOrPassword)
- [`StatusMalformedEmail`](#StatusMalformedEmail)
- [`StatusVerificationTokenInvalid`](#StatusVerificationTokenInvalid)
- [`StatusVerificationTokenExpired`](#StatusVerificationTokenExpired)
- [`StatusProposalMissingName`](#StatusProposalMissingName)
- [`StatusProposalMissingDescription`](#StatusProposalMissingDescription)
- [`StatusProposalNotFound`](#StatusProposalNotFound)
- [`StatusMaxMDsExceededPolicy`](#StatusMaxMDsExceededPolicy)
- [`StatusMaxImagesExceededPolicy`](#StatusMaxImagesExceededPolicy)
- [`StatusMaxMDSizeExceededPolicy`](#StatusMaxMDSizeExceededPolicy)
- [`StatusMaxImageSizeExceededPolicy`](#StatusMaxImageSizeExceededPolicy)

### Methods

#### `Version`

Obtain version, route information and signing identity from server.  This call
shall **ALWAYS** be the first contact with the server.  This is done in order
to get the CSRF token for the session and to ensure API compatability.

* **URL**

  `/`

* **HTTP Method:**

  `GET`

*  *Params*

* **Results**

`Version`

API version that is running on this server.

`Route`

Route that should be prepended to all calls.  For example, `v1`.

`Identity`

Identity that signs various tokens to ensure server authenticity and to prevent
replay attacks.

On success the call returns `HTTP Status: 200 OK`.
On Failure the call returns `HTTP Status: 500 Internal Server Error`.

* **Example**

Request:
```json
{}
```

Reply:

```json
{
	"version":1,
	"route":"/v1",
	"identity":"99e748e13d7ecf70ef6b5afa376d692cd7cb4dbb3d26fa83f417d29e44c6bb6c",
}
```

#### `Me`

Return pertinent user information of the current logged in user.

* **URL**

  `/user/me`

* **HTTP Method:**

  `GET`

*  *Params*

* **Results**

`Email`

User ID.

`IsAdmin`

Administrator indicator.

On success the call returns `HTTP Status: 200 OK`.
If there currently is no session the call returns `HTTP Status: 403 Forbidden`.

The me call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

* **Example**

Request:
```json
{}
```

Reply:

```json
{
    "email":"d3a948d856daea3d@example.com",
    "isadmin":true,
    "errorcode":1,
}
```

#### `New user`

Create a new user on the politeiawww server.

* **URL**

  `/v1/user/new`

* **HTTP Method:**

  `POST`

*  *Params*

**Required**

`email=[string]`

Email is used as the web site user identity for a user.  When a user changes
email addresses the server shall maintain a mapping between the old and new
address.

`password=[string]`

The password that the user wishes to use.  This password travels in the clear
in order to enable JS-less systems.  The server shall never store passwords in
the clear.

* **Results**

`errorcode`

On Success the call shall return `200 OK` and the error code shall be set to
one of the following statusses:
- [`StatusSuccess`](#StatusSuccess).
- [`StatusInvalidEmailOrPassword`](#StatusInvalidEmailOrPassword)
- [`StatusMalformedEmail`](#StatusMalformedEmail)

The login call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

* **Example**

Request:

```json
{
    "email":"15a1eb6de3681fec@example.com",
    "password":"15a1eb6de3681fec",
}
```

Reply:

```json
{
    "verificationtoken":"f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde",
    "errorcode":1
}
```

#### `Verify user`

Verify email address of a previously created user.

* **URL**

  `/v1/user/verify`

* **HTTP Method:**

  `GET`

*  *Params*

**Required**

`email=[string]`

Email address of previously created user.

`verificationtoken=[string]`

The token that was provided by email to the user.

* **Results**

`errorcode`

On Success the call shall return `200 OK` and the error code shall be set to
[`StatusSuccess`](#StatusSuccess).
Additionally the browser will be redirected to `/v1/user/verify/success`.

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`StatusInvalidEmailOrPassword`](#StatusInvalidEmailOrPassword)
- [`StatusMalformedEmail`](#StatusMalformedEmail)
- [`StatusVerificationTokenInvalid`](#StatusVerificationTokenInvalid)
- [`StatusVerificationTokenExpired`](#StatusVerificationTokenExpired)
Additionally the browser will be redirected to `/v1/user/verify/failure`.

* **Example**

Request:

The request params should be provided within the URL:

```
/v1/user/verify?email=abc@example.com&verificationtoken=f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde
```

Reply:

The user verification command is special.  It does not return a JSON reply,
instead it redirects to `/v1/user/verify/success` on success or to
`/v1/user/verify/failure` on failure.

#### `Login`

Login as a user or admin.  Admin status is determined by the server based on
the user database.

* **URL**

  `/v1/login`

* **HTTP Method:**

  `POST`

*  *Params*

**Required**

`email=[string]`

Email address of user that is attempting to login.

`password=[string]`

Accompanying password for provided email.

* **Results**

`isadmin`

The `isadmin` flag is indicates if the user has publish/censor privileges.
`errorcode`

On Success the call shall return `200 OK` and the error code shall be set to
[`StatusSuccess`](#StatusSuccess).

On login failure the call shall return `403 Forbidden` and one of the following
error codes:
- [`StatusInvalidEmailOrPassword`](#StatusInvalidEmailOrPassword)

The login call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

* **Example**

Request:

```json
{
    "email":"6b87b6ebb0c80cb7@example.com",
    "password":"6b87b6ebb0c80cb7",
}
```

Reply:

```json
{
    "isadmin":"false",
    "errorcode":"1",
}
```

#### `Logout`

Logout as a user or admin.

* **URL**

  `/v1/logout`

* **HTTP Method:**

  `GET` or `POST`

*  *Params*

**Required**

```
N/A
```

* **Results**

`errorcode`

On Success the call shall return `200 OK` and the error code shall be set to
[`StatusSuccess`](#StatusSuccess).

The logout call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

* **Example**

Request:

```json
{}
```

Reply:

```json
    "errorcode":1
```

#### `New proposal`

Submit a new proposal to the politeiawww server.

* **URL**

  `/v1/proposal/new`

* **HTTP Method:**

  `POST`

*  *Params*

**Required**

`name=[string]`

Name of the proposal.  This should be a reasonably small title that describes
the proposal.

`Files=[[]File]`

Files are the body of the proposal.  It should consist of one markdown file and
up to five pictures.

The structure of the file is as follows:
	`name=[string]`

Name is the suggested filename.  There should be no filenames that are
overlapping and the name shall be validated before being used.

	`mime=[string]`

MIME type of the payload.  Currently the system only supports md and png/svg
files.  The server shall reject invalid MIME types.

	`digest=[string]`

Digest is a SHA256 digest of the payload.  The digest shall be verified by
politeiawww.

	`payload=[string]`

Payload is the actual file content.  It shall be base64 encoded.  Files have
size limits that can be obtained via the [`Policy`](#Policy) call.  The server
shall strictly enforce policy limits.

* **Results**

`errorcode`

On Success the call shall return `200 OK` and the error code shall be set to
[`StatusSuccess`](#StatusSuccess).

Additionally the call returns a censorship record that provides the submitter
with a method to extract the proposal and prove that he/she submitted it.  The
censorship record is defined as follows:

	token=[string]

The toke is a 32 byte random number that was assigned to identify the submitted
proposal.  This is the key to later retrieve the submitted proposal from the
system.

	merkle=[string]

Merkle root of the proposal.  This is defined as the *sorted* digests of all
files proposal files.  The client should cross verify this value.

	signature=[string]

Signature of merkle+token.  The token is appended to the merkle root and then
signed.  The client should verify the signature.

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`StatusProposalMissingName`](#StatusProposalMissingName)
- [`StatusProposalMissingDescription`](#StatusProposalMissingDescription)
- [`StatusMaxMDsExceededPolicy`](#StatusMaxMDsExceededPolicy)
- [`StatusMaxImagesExceededPolicy`](#StatusMaxImagesExceededPolicy)
- [`StatusMaxMDSizeExceededPolicy`](#StatusMaxMDSizeExceededPolicy)
- [`StatusMaxImageSizeExceededPolicy`](#StatusMaxImageSizeExceededPolicy)

* **Example**

Request:

```json
// XXX refclient doesn't send digest along and server does not freak out, fix both issues
{
    "name":"test",
    "files":[{
        "name":"index.md",
	"mime":"text/plain; charset=utf-8",
	"digest":"",
	"payload":"VGhpcyBpcyBhIGRlc2NyaXB0aW9u"
    }]
}
```

Reply:

```json
{
    "censorshiprecord":{
        "token":"337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
	"merkle":"0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
	"signature":"fcc92e26b8f38b90c2887259d88ce614654f32ecd76ade1438a0def40d360e461d995c796f16a17108fad226793fd4f52ff013428eda3b39cd504ed5f1811d0d"
    },
    "errorcode":1
}
```

#### `Unvetted`

Retrieve all unvetted proposals.  This call requires admin privileges.

* **URL**

  `/v1/unvetted`

* **HTTP Method:**

  `GET`

*  *Params*

**Required**

```
N/A
```

* **Results**

`errorcode`

On Success the call shall return `200 OK` and the error code shall be set to
[`StatusSuccess`](#StatusSuccess).  Note: provided that the caller has
privileges the call does not fail.

If the caller is not privileged the unvetted call returns `403 Forbidden`.

* **Example**

# unvetted example

Request:

```json
{}
```

Reply:

```json
    "proposals":[],
    "errorcode":1
```

#### `Vetted`

Retrieve all vetted proposals.

* **URL**

  `/v1/vetted`

* **HTTP Method:**

  `GET`

*  *Params*

**Required**

```
N/A
```

* **Results**

`errorcode`

On Success the call shall return `200 OK` and the error code shall be set to
[`StatusSuccess`](#StatusSuccess). This call does not fail.

* **Example**

# vetted example

Request:

```json
{}
```

Reply:

```json
    "proposals":[],
    "errorcode":1
```

#### `Policy`

Retrieve server policy.  The returned values contain various maxima that the client
SHALL observe.

* **URL**

  `/v1/policy`

* **HTTP Method:**

  `GET`

*  *Params*

**Required**

```
N/A
```

* **Results**

`errorcode`

On Success the call shall return `200 OK` and the error code shall be set to
[`StatusSuccess`](#StatusSuccess). This call does not fail.

* **Example**

# policy example

Request:

```json
{}
```

Reply:

```json
    "maximages":5,
    "maximagesize":524288,
    "maxmds":1,
    "maxmdsize":524288,
    "validmimetypes":[
        "image/png",
        "image/svg+xml",
	"text/plain",
	"text/plain; charset=utf-8"
    ],
    "errorcode":1
```

#### `Set proposal status`

Set status of proposal to `published` or `censored`.  This call is privileged.

* **URL**

  `/v1/proposals/{token:[A-z0-9]{64}}/setstatus`

* **HTTP Method:**

  `POST`

*  *Params*

**Required**

`token=[string]`

Token is the unique censorship token that identifies a specific proposal.

`status=[statusT]`

Status indicates the new status for the proposal.  Valid status are:
 - StatusCensored = `3`
 - StatusPublic = `4`

Status can only be changed if the current proposal status is `2` or
StatusNotReviewed.

* **Results**

`errorcode`

On Success the call shall return `200 OK` and the error code shall be set to
[`StatusSuccess`](#StatusSuccess).

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`StatusProposalNotFound`](#StatusProposalNotFound)

* **Example**

Request:

```json
// XXX refclient doesn't send digest along and server does not freak out, fix both issues
{
    "name":"test",
    "files":[{
        "name":"index.md",
	"mime":"text/plain; charset=utf-8",
	"digest":"",
	"payload":"VGhpcyBpcyBhIGRlc2NyaXB0aW9u"
    }]
}
```

Reply:

```json
{
    "censorshiprecord":{
        "token":"337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
	"merkle":"0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
	"signature":"fcc92e26b8f38b90c2887259d88ce614654f32ecd76ade1438a0def40d360e461d995c796f16a17108fad226793fd4f52ff013428eda3b39cd504ed5f1811d0d"
    },
    "errorcode":1
}
```

#### `Proposal details`

Retrieve proposal and its details.

* **URL**

  `/v1/proposals/{token:[A-z0-9]{64}}`

* **HTTP Method:**

  `POST`

*  *Params*

**Required**

`N/A`

* **Results**

`errorcode`

On Success the call shall return `200 OK` and the error code shall be set to
[`StatusSuccess`](#StatusSuccess).

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`StatusProposalNotFound`](#StatusProposalNotFound)

The proposal details call may return `500 Internal Server Error` which is
accompanied by an error code that allows the server operator to correlate
issues with user reports.

* **Example**

Request:

```json
{}
```

Reply:

```json
{
    "proposal":{
        "name":"test",
	"status":3,
	"timestamp":1508146426,
	"files":[{
	    "name":"index.md",
	    "mime":"text/plain; charset=utf-8",
	    "digest":"0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
	    "payload":"VGhpcyBpcyBhIGRlc2NyaXB0aW9u"
	}],
	"censorshiprecord":{
	    "token":"c378e0735b5650c9e79f70113323077b107b0d778547f0d40592955668f21ebf",
	    "merkle":"0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
	    "signature":"f5ea17d547d8347a2f2d77edcb7e89fcc96613d7aaff1f2a26761779763d77688b57b423f1e7d2da8cd433ef2cfe6f58c7cf1c43065fa6716a03a3726d902d0a"
	}},
    "errorcode":1
}
```

### Status codes

* `StatusInvalid`

	`0`

The operation returned an invalid status.  This shall be considered a bug.

* `StatusSuccess`

	`1`

The operation was successful.

* `StatusInvalidEmailOrPassword`

	`2`

Either the user name or password was invalid.

* `StatusMalformedEmail`

	`3`

The provided email address was malformed.

* `StatusVerificationTokenInvalid`

	`4`

The provided user activation token is invalid.

* `StatusVerificationTokenExpired`

	`5`

The provided user activation token is expired.

* `StatusProposalMissingName`

	`6`

The provided proposal does not have a short name.

* `StatusProposalMissingDescription`

	`7`

The provided proposal does not have a description.

* `StatusProposalNotFound`

	`8`

The requested proposal does not exist.

* `StatusMaxMDsExceededPolicy`

	`9`

The submitted proposal's has too many markdown files.  Limits can be obtained
by issuing the [`Policy`](#Policy) command.

* `StatusMaxImagesExceededPolicy`

	`10`

The submitted proposal's has too many images.  Limits can be obtained by
issuing the [`Policy`](#Policy) command.

* `StatusMaxMDSizeExceededPolicy`

	`11`

The submitted proposal's markdown is too large.  Limits can be obtained by
issuing the [`Policy`](#Policy) command.

* `StatusMaxImageSizeExceededPolicy`

	`12`

The submitted proposal's has one or more images that are too large.  Limits can
be obtained by issuing the [`Policy`](#Policy) command.
