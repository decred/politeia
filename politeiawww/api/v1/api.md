# politeiawww API Specification

# v1

This document describes the REST API provided by a `politeiawww` server.  The
`politeiawww` server is the web server backend and it interacts with a JSON REST
API.  It does not render HTML.

**Methods**

- [`Version`](#version)
- [`New user`](#new-user)
- [`Verify user`](#verify-user)
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
- [`StatusMalformedPassword`](#StatusMalformedPassword)

**Proposal status codes**

- [`PropStatusInvalid`](#PropStatusInvalid)
- [`PropStatusNotFound`](#PropStatusNotFound)
- [`PropStatusNotReviewed`](#PropStatusNotReviewed)
- [`PropStatusCensored`](#PropStatusCensored)
- [`PropStatusPublic`](#PropStatusPublic)

## Methods

### `Version`

Obtain version, route information and signing identity from server.  This call
shall **ALWAYS** be the first contact with the server.  This is done in order
to get the CSRF token for the session and to ensure API compatability.

**Route**: `GET /`

**Params**: none

**Results**:

<table>
  <tbody>
    <tr>
      <th></th>
      <th>Type</th>
      <th>Description</th>
    </tr>
    <tr>
      <td><code>version</code></td>
      <td>Number</td>
      <td>API version that is running on this server.</td>
    </tr>
    <tr>
      <td><code>route</code></td>
      <td>String</td>
      <td>
        Route that should be prepended to all calls.  For example, <code>"/v1"</code>.
      </td>
    </tr>
    <tr>
      <td><code>identity</code></td>
      <td>String</td>
      <td>
        Identity that signs various tokens to ensure server authenticity and
        to prevent replay attacks.
      </td>
    </tr>
  </tbody>
</table>

On success the call shall return `200 OK` and the error code shall be set to
[`StatusSuccess`](#StatusSuccess).

The call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

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

<table>
  <tbody>
    <tr>
      <th></th>
      <th>Type</th>
      <th>Description</th>
    </tr>
    <tr>
      <td><code>email</code></td>
      <td>String</td>
      <td>User ID.</td>
    </tr>
    <tr>
      <td><code>isadmin</code></td>
      <td>String</td>
      <td>This indicates if the user has publish/censor privileges.</td>
    </tr>
  </tbody>
</table>

On success the call shall return `200 OK` and the error code shall be set to
[`StatusSuccess`](#StatusSuccess). If there currently is no session the call
returns `403 Forbidden`.

The call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

**Example**

Request:

```json
{}
```

Reply:

```json
{
  "email": "d3a948d856daea3d@example.com",
  "isadmin": true,
  "errorcode": 1
}
```

### `New user`

Create a new user on the politeiawww server.

**Route:** `POST /v1/user/new`

**Params:**

<table>
  <tbody>
    <tr>
      <th>Parameter</th>
      <th>Type</th>
      <th>Description</th>
      <th>Required</th>
    </tr>
    <tr>
      <td><code>email</code></td>
      <td>String</td>
      <td>
        Email is used as the web site user identity for a user.  When a user
        changes email addresses the server shall maintain a mapping between
        the old and new address.
      </td>
      <td>Yes</td>
    </tr>
    <tr>
      <td><code>password</code></td>
      <td>String</td>
      <td>
        The password that the user wishes to use.  This password travels in the
        clear in order to enable JS-less systems.  The server shall never store
        passwords in the clear.
      </td>
      <td>Yes</td>
    </tr>
  </tbody>
</table>

**Results:**

<table>
  <tbody>
    <tr>
      <th></th>
      <th>Type</th>
      <th>Description</th>
    </tr>
    <tr>
      <td><code>errorcode</code></td>
      <td>Number</td>
      <td>One of the <a href="#status-codes">status codes</a>.</td>
    </tr>
    <tr>
      <td><code>verificationtoken</code></td>
      <td>String</td>
      <td>
        The verification token which is required when calling
        <a href="#verify-user"><code>Verify user</code></a>.  If an email server
        is set up, this property will be empty or nonexistent; the token will
        be sent to the email address sent in the request.
      </td>
    </tr>
  </tbody>
</table>

On success the call shall return `200 OK` and the error code shall be set to
one of the following statuses:

- [`StatusSuccess`](#StatusSuccess)
- [`StatusInvalidEmailOrPassword`](#StatusInvalidEmailOrPassword)
- [`StatusMalformedEmail`](#StatusMalformedEmail)

The email shall include a link in the following format:

```
/user/verify?email=abc@example.com&verificationtoken=f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde
```

The call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

* **Example**

Request:

```json
{
  "email": "15a1eb6de3681fec@example.com",
  "password": "15a1eb6de3681fec"
}
```

Reply:

```json
{
  "verificationtoken": "f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde",
  "errorcode": 1
}
```

### `Verify user`

Verify email address of a previously created user.

**Route:** `GET /v1/user/verify`

**Params:**

<table>
  <tbody>
    <tr>
      <th>Parameter</th>
      <th>Type</th>
      <th>Description</th>
      <th>Required</th>
    </tr>
    <tr>
      <td><code>email</code></td>
      <td>String</td>
      <td>Email address of previously created user.</td>
      <td>Yes</td>
    </tr>
    <tr>
      <td><code>verificationtoken</code></td>
      <td>String</td>
      <td>The token that was provided by email to the user.</td>
      <td>Yes</td>
    </tr>
  </tbody>
</table>

**Results:**

<table>
  <tbody>
    <tr>
      <th></th>
      <th>Type</th>
      <th>Description</th>
    </tr>
    <tr>
      <td><code>errorcode</code></td>
      <td>Number</td>
      <td>One of the <a href="#status-codes">status codes</a>.</td>
    </tr>
  </tbody>
</table>

On success the call shall redirect to `/v1/user/verify/success` which will return
`200 OK`, and the error code shall be set to [`StatusSuccess`](#StatusSuccess).

On failure the call shall redirect to `/v1/user/verify/failure` which will return
`400 Bad Request` and one of the following error codes:
- [`StatusVerificationTokenInvalid`](#StatusVerificationTokenInvalid)
- [`StatusVerificationTokenExpired`](#StatusVerificationTokenExpired)

The call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

**Example:**

Request:

The request params should be provided within the URL:

```
/v1/user/verify?email=abc@example.com&verificationtoken=f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde
```

Reply:

The user verification command is special.  It redirects to `/v1/user/verify/success`
on success or to `/v1/user/verify/failure` on failure, which return the JSON:

```json
{
  "errorcode": 1
}
```

### `Login`

Login as a user or admin.  Admin status is determined by the server based on
the user database.

**Route:** `POST /v1/login`

**Params:**

<table>
  <tbody>
    <tr>
      <th>Parameter</th>
      <th>Type</th>
      <th>Description</th>
      <th>Required</th>
    </tr>
    <tr>
      <td><code>email</code></td>
      <td>String</td>
      <td>Email address of user that is attempting to login.</td>
      <td>Yes</td>
    </tr>
    <tr>
      <td><code>password</code></td>
      <td>String</td>
      <td>Accompanying password for provided email.</td>
      <td>Yes</td>
    </tr>
  </tbody>
</table>

**Results:**

<table>
  <tbody>
    <tr>
      <th></th>
      <th>Type</th>
      <th>Description</th>
    </tr>
    <tr>
      UserID uint64 User identifier
      <td><code>isadmin</code></td>
      <td>Boolean</td>
      <td>This indicates if the user has publish/censor privileges.</td>
    </tr>
    <tr>
      <td><code>errorcode</code></td>
      <td>Number</td>
      <td>One of the <a href="#status-codes">status codes</a>.</td>
    </tr>
  </tbody>
</table>

On success the call shall return `200 OK` and the error code shall be set to
[`StatusSuccess`](#StatusSuccess).

On failure the call shall return `403 Forbidden` and one of the following
error codes:
- [`StatusInvalidEmailOrPassword`](#StatusInvalidEmailOrPassword)

The call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

**Example**

Request:

```json
{
  "email": "6b87b6ebb0c80cb7@example.com",
  "password": "6b87b6ebb0c80cb7"
}
```

Reply:

```json
{
  "isadmin": false,
  "errorcode": 1
}
```

### `Logout`

Logout as a user or admin.

**Route:** `POST /v1/logout`

**Params:** none

**Results:**

<table>
  <tbody>
    <tr>
      <th></th>
      <th>Type</th>
      <th>Description</th>
    </tr>
    <tr>
      <td><code>errorcode</code></td>
      <td>Number</td>
      <td>One of the <a href="#status-codes">status codes</a>.</td>
    </tr>
  </tbody>
</table>

On success the call shall return `200 OK` and the error code shall be set to
[`StatusSuccess`](#StatusSuccess).

The call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

**Example**

Request:

```json
{}
```

Reply:

```json
{
  "errorcode": 1
}
```

### `Change password`

Changes the password for the currently logged in user.

**Route:** `POST /v1/user/password/change`

**Params:**

<table>
  <tbody>
    <tr>
      <th>Parameter</th>
      <th>Type</th>
      <th>Description</th>
      <th>Required</th>
    </tr>
    <tr>
      <td><code>currentpassword</code></td>
      <td>String</td>
      <td>The current password of the logged in user.</td>
      <td>Yes</td>
    </tr>
    <tr>
      <td><code>newpassword</code></td>
      <td>String</td>
      <td>The new password for the logged in user.</td>
      <td>Yes</td>
    </tr>
  </tbody>
</table>

**Results**

<table>
  <tbody>
    <tr>
      <th></th>
      <th>Type</th>
      <th>Description</th>
    </tr>
    <tr>
      <td><code>errorcode</code></td>
      <td>Number</td>
      <td>One of the <a href="#status-codes">status codes</a>.</td>
    </tr>
  </tbody>
</table>

On success the call shall return `200 OK` and the error code shall be set to
[`StatusSuccess`](#StatusSuccess).

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`StatusInvalidEmailOrPassword`](#StatusInvalidEmailOrPassword)
- [`StatusMalformedPassword`](#StatusMalformedPassword)

The call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

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
{
  "errorcode": 1
}
```

### `Reset password`

Allows a user to reset his password without being logged in.

**Route:** `POST /v1/user/password/reset`

**Params:**

<table>
  <tbody>
    <tr>
      <th>Parameter</th>
      <th>Type</th>
      <th>Description</th>
      <th>Required</th>
    </tr>
    <tr>
      <td><code>email</code></td>
      <td>String</td>
      <td>The email of the user whose password should be reset.</td>
      <td>Yes</td>
    </tr>
    <tr>
      <td><code>verificationtoken</code></td>
      <td>String</td>
      <td>The verification token which is sent to the user's email address.</td>
      <td>Yes</td>
    </tr>
    <tr>
      <td><code>newpassword</code></td>
      <td>String</td>
      <td>The new password for the user.</td>
      <td>Yes</td>
    </tr>
  </tbody>
</table>

**Results:**

<table>
  <tbody>
    <tr>
      <th></th>
      <th>Type</th>
      <th>Description</th>
    </tr>
    <tr>
      <td><code>errorcode</code></td>
      <td>Number</td>
      <td>One of the <a href="#status-codes">status codes</a>.</td>
    </tr>
  </tbody>
</table>

The reset password command is special.  It must be called **twice** with different
parameters.

For the 1st call, it should be called with only an `email` parameter. On success
it shall send an email to the address provided by `email` and return `200 OK`
and the `errorcode` shall be set to [`StatusSuccess`](#StatusSuccess).

The email shall include a link in the following format:

```
/user/password/reset?email=abc@example.com&verificationtoken=f1c2042d36c8603517cf24768b6475e18745943e4c6a20bc0001f52a2a6f9bde
```

On failure, the call shall return `400 Bad Request` and one of the following
error codes:
- [`StatusMalformedEmail`](#StatusMalformedEmail)

For the 2nd call, it should be called with `email`, `token`, and `newpassword`
parameters. On success it shall return `200 OK` and the `errorcode` shall be set
to [`StatusSuccess`](#StatusSuccess).

On failure, the call shall return `400 Bad Request` and one of the following
error codes:
- [`StatusVerificationTokenInvalid`](#StatusVerificationTokenInvalid)
- [`StatusVerificationTokenExpired`](#StatusVerificationTokenExpired)
- [`StatusMalformedPassword`](#StatusMalformedPassword)

The call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

**Example for the 1st call**

Request:

```json
{
  "email": "6b87b6ebb0c80cb7@example.com"
}
```

Reply:

```json
{
  "errorcode": 1
}
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
  "errorcode": 1
}
```

### `New proposal`

Submit a new proposal to the politeiawww server.

**Route:** `POST /v1/proposal/new`

**Params:**

<table>
  <tbody>
    <tr>
      <th>Parameter</th>
      <th>Type</th>
      <th>Description</th>
      <th>Required</th>
    </tr>
    <tr>
      <td><code>name</code></td>
      <td>String</td>
      <td>
        Name of the proposal.  This should be a reasonably small title that
        describes the proposal.
      </td>
      <td>Yes</td>
    </tr>
    <tr>
      <td><code>files</code></td>
      <td>Array of Objects</td>
      <td>
        <p>Files are the body of the proposal.  It should consist of one markdown
        file and up to five pictures.  The structure of the file is as follows:</p>
        <table>
          <tbody>
            <tr>
              <th>Parameter</th>
              <th>Type</th>
              <th>Description</th>
              <th>Required</th>
            </tr>
            <tr>
              <td><code>name</code></td>
              <td>String</td>
              <td>
                Name is the suggested filename.  There should be no filenames
                that are overlapping and the name shall be validated before being used.
              </td>
              <td>Yes</td>
            </tr>
            <tr>
              <td><code>mime</code></td>
              <td>String</td>
              <td>
                MIME type of the payload.  Currently the system only supports
                md and png/svg files.  The server shall reject invalid MIME types.
              </td>
              <td>Yes</td>
            </tr>
            <tr>
              <td><code>digest</code></td>
              <td>String</td>
              <td>
                Digest is a SHA256 digest of the payload.  The digest shall be
                verified by politeiawww.
              </td>
              <td>Yes</td>
            </tr>
            <tr>
              <td><code>payload</code></td>
              <td>String</td>
              <td>
                Payload is the actual file content.  It shall be base64 encoded.
                Files have size limits that can be obtained via the
                <a href="#Policy"><code>Policy</code></a> call.  The server shall
                strictly enforce policy limits.
              </td>
              <td>Yes</td>
            </tr>
          </tbody>
        </table>
      </td>
      <td>Yes</td>
    </tr>
  </tbody>
</table>

**Results:**

<table>
  <tbody>
    <tr>
      <th></th>
      <th>Type</th>
      <th>Description</th>
    </tr>
    <tr>
      <td><code>censorshiprecord</code></td>
      <td><a href="#censorship-record"><code>CensorshipRecord</code></a></td>
      <td>
        <p>A censorship record that provides the submitter with a method to extract
        the proposal and prove that he/she submitted it.</p>
      </td>
    </tr>
    <tr>
      <td><code>errorcode</code></td>
      <td>Number</td>
      <td>One of the <a href="#status-codes">status codes</a>.</td>
    </tr>
  </tbody>
</table>

On success the call shall return `200 OK` and the error code shall be set to
[`StatusSuccess`](#StatusSuccess).

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`StatusProposalMissingName`](#StatusProposalMissingName)
- [`StatusProposalMissingDescription`](#StatusProposalMissingDescription)
- [`StatusMaxMDsExceededPolicy`](#StatusMaxMDsExceededPolicy)
- [`StatusMaxImagesExceededPolicy`](#StatusMaxImagesExceededPolicy)
- [`StatusMaxMDSizeExceededPolicy`](#StatusMaxMDSizeExceededPolicy)
- [`StatusMaxImageSizeExceededPolicy`](#StatusMaxImageSizeExceededPolicy)

The call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

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
  },
  "errorcode": 1
}
```

### `Unvetted`

Retrieve all unvetted proposals.  This call requires admin privileges.

**Route:** `GET /v1/unvetted`

**Params:** none

**Results:**

<table>
  <tbody>
    <tr>
      <th></th>
      <th>Type</th>
      <th>Description</th>
    </tr>
    <tr>
      <td><code>proposals</code></td>
      <td>Array of Objects</td>
      <td>
        <p>An Array of unvetted proposals, each of which has the following structure:</p>
        <table>
          <tbody>
            <tr>
              <th></th>
              <th>Type</th>
              <th>Description</th>
            </tr>
            <tr>
              <td><code>name</code></td>
              <td>String</td>
              <td>The name of the proposal.</td>
            </tr>
            <tr>
              <td><code>status</code></td>
              <td>Number</td>
              <td>Current status of the proposal.</td>
            </tr>
            <tr>
              <td><code>timestamp</code></td>
              <td>Number</td>
              <td>The unix time of the last update of the proposal.</td>
            </tr>
            <tr>
              <td><code>censorshiprecord</code></td>
              <td><a href="#censorship-record"><code>CensorshipRecord</code></a></td>
              <td>
                <p>The censorship record that was created when the proposal was
                submitted.</p>
              </td>
            </tr>
          </tbody>
        </table>
      </td>
    </tr>
    <tr>
      <td><code>errorcode</code></td>
      <td>Number</td>
      <td>One of the <a href="#status-codes">status codes</a>.</td>
    </tr>
  </tbody>
</table>

On success the call shall return `200 OK` and the error code shall be set to
[`StatusSuccess`](#StatusSuccess).  Note: This is provided that the caller has
the required privileges.

If the caller is not privileged the unvetted call returns `403 Forbidden`.

The call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

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
  }],
  "errorcode": 1
```

### `Vetted`

Retrieve all vetted proposals.

**Route:** `GET /v1/vetted`

**Params:** none

**Results:**

<table>
  <tbody>
    <tr>
      <th></th>
      <th>Type</th>
      <th>Description</th>
    </tr>
    <tr>
      <td><code>errorcode</code></td>
      <td>Number</td>
      <td>One of the <a href="#status-codes">status codes</a>.</td>
    </tr>
  </tbody>
</table>

On success the call shall return `200 OK` and the error code shall be set to
[`StatusSuccess`](#StatusSuccess). This call does not fail.

The call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

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
    "censorshiprecord": {
      "token": "337fc4762dac6bbe11d3d0130f33a09978004b190e6ebbbde9312ac63f223527",
      "merkle": "0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8",
      "signature": "fcc92e26b8f38b90c2887259d88ce614654f32ecd76ade1438a0def40d360e461d995c796f16a17108fad226793fd4f52ff013428eda3b39cd504ed5f1811d0d"
    }
  }],
  "errorcode": 1
```

### `Policy`

Retrieve server policy.  The returned values contain various maxima that the client
SHALL observe.

**Route:** `GET /v1/policy`

**Params:** none

**Results:**

<table>
  <tbody>
    <tr>
      <th></th>
      <th>Type</th>
      <th>Description</th>
    </tr>
    <tr>
      <td><code>errorcode</code></td>
      <td>Number</td>
      <td>One of the <a href="#status-codes">status codes</a>.</td>
    </tr>
  </tbody>
</table>

On success the call shall return `200 OK` and the error code shall be set to
[`StatusSuccess`](#StatusSuccess). This call does not fail.

The call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

**Example**

Request:

```json
{}
```

Reply:

```json
{
  "passwordminchars": 8,
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
  "errorcode": 1
}
```

### `Set proposal status`

Set status of proposal to `PropStatusPublic` or `PropStatusCensored`.  This call requires admin
privileges.

**Route:** `POST /v1/proposals/{token}/status`

**Params:**

<table>
  <tbody>
    <tr>
      <th>Parameter</th>
      <th>Type</th>
      <th>Description</th>
      <th>Required</th>
    </tr>
    <tr>
      <td><code>token</code></td>
      <td>String</td>
      <td>
        Token is the unique censorship token that identifies a specific proposal.
      </td>
      <td>Yes</td>
    </tr>
    <tr>
      <td><code>status</code></td>
      <td>Number</td>
      <td>
        <p>Status indicates the new status for the proposal.  Valid statuses are:</p>
        <ul>
          <li><a href="#PropStatusCensored"><code>PropStatusCensored</code></a></li>
          <li><a href="#PropStatusPublic"><code>PropStatusPublic</code></a></li>
        </ul>
        <p>
          Status can only be changed if the current proposal status is
          <a href="#PropStatusNotReviewed"><code>PropStatusNotReviewed</code></a>
        </p>
      </td>
      <td>Yes</td>
    </tr>
  </tbody>
</table>

**Results**

<table>
  <tbody>
    <tr>
      <th></th>
      <th>Type</th>
      <th>Description</th>
    </tr>
    <tr>
      <td><code>errorcode</code></td>
      <td>Number</td>
      <td>One of the <a href="#status-codes">status codes</a>.</td>
    </tr>
  </tbody>
</table>

On success the call shall return `200 OK` and the error code shall be set to
[`StatusSuccess`](#StatusSuccess).

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`StatusProposalNotFound`](#StatusProposalNotFound)

The call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

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
  "status": 4,
  "errorcode": 1
}
```

### `Proposal details`

Retrieve proposal and its details.

**Routes:** `POST /v1/proposals/{token}`

**Params:** none

**Results:**

<table>
  <tbody>
    <tr>
      <th></th>
      <th>Type</th>
      <th>Description</th>
    </tr>
    <tr>
      <td><code>errorcode</code></td>
      <td>Number</td>
      <td>One of the <a href="#status-codes">status codes</a>.</td>
    </tr>
  </tbody>
</table>

On success the call shall return `200 OK` and the error code shall be set to
[`StatusSuccess`](#StatusSuccess).

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`StatusProposalNotFound`](#StatusProposalNotFound)

The call may return `500 Internal Server Error` which is accompanied by
an error code that allows the server operator to correlate issues with user
reports.

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
  },
  "errorcode": 1
}
```

### `New comment`

Submit comment on given proposal.  ParentID value 0 means "comment on
proposal"; non-zero values mean "reply to comment".

**Route:** `POST /v1/comments/new`

**Params:**

| Parameter | Type | Description | Required |
| - | - | - | - |
| Token | string | Censorship token | Yes |
| ParentID | uint64 | Parent comment | Yes |
| Comment | string | Comment | Yes |

**Results:**

| | Type | Description |
| - | - | - |
| CommentID | uint64 | Server generated comment ID |
| ErrorCode | StatusT | Error code |

**Example**

Request:

```json
{
  "token":"86221ddae6594b43a19e4c76250c0a8833ecd3b7a9880fb5d2a901970de9ff0e",
  "parentid":53,
  "comment":"you are right!"}
}
```

Reply:

```json
{
  "commentid":103,
  "errorcode":1
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
| ErrorCode | StatusT | Error code |

**Comment:**

| | Type | Description |
| - | - | - |
| CommentID | uint64 | Unique comment identifier |
| UserID | uint64 | Unique user identifier |
| ParentID | uint64 | Parent comment |
| Timestamp | int64 | UNIX time when comment was accepted |
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
    "commentid":56,
    "userid":4,
    "parentid":0,
    "timestamp":1509990301,
    "token":"86221ddae6594b43a19e4c76250c0a8833ecd3b7a9880fb5d2a901970de9ff0e",
    "comment":"I dont like this prop"
  },{
    "commentid":57,
    "userid":4,
    "parentid":56,
    "timestamp":1509990301,
    "token":"86221ddae6594b43a19e4c76250c0a8833ecd3b7a9880fb5d2a901970de9ff0e",
    "comment":"you are right!"
  },{
    "commentid":58,
    "userid":4,
    "parentid":56,
    "timestamp":1509990301,
    "token":"86221ddae6594b43a19e4c76250c0a8833ecd3b7a9880fb5d2a901970de9ff0e",
    "comment":"you are crazy!"
  }]
}
```

### Status codes

<table>
  <tbody>
    <tr>
      <th>Status</th>
      <th>Value</th>
      <th>Description</th>
    </tr>
    <tr>
      <td><a name="StatusInvalid"><code>StatusInvalid</code></a></td>
      <td>0</td>
      <td>The operation returned an invalid status.  This shall be considered a bug.</td>
    </tr>
    <tr>
      <td>
        <a name="StatusSuccess">
          <code>StatusSuccess</code>
        </a>
      </td>
      <td>1</td>
      <td>The operation was successful.</td>
    </tr>
    <tr>
      <td>
        <a name="StatusInvalidEmailOrPassword">
          <code>StatusInvalidEmailOrPassword</code>
        </a>
      </td>
      <td>2</td>
      <td>Either the user name or password was invalid.</td>
    </tr>
    <tr>
      <td>
        <a name="StatusMalformedEmail">
          <code>StatusMalformedEmail</code>
        </a>
      </td>
      <td>3</td>
      <td>The provided email address was malformed.</td>
    </tr>
    <tr>
      <td>
        <a name="StatusVerificationTokenInvalid">
          <code>StatusVerificationTokenInvalid</code>
        </a>
      </td>
      <td>4</td>
      <td>The provided user activation token is invalid.</td>
    </tr>
    <tr>
      <td>
        <a name="StatusVerificationTokenExpired">
          <code>StatusVerificationTokenExpired</code>
        </a>
      </td>
      <td>5</td>
      <td>The provided user activation token is expired.</td>
    </tr>
    <tr>
      <td>
        <a name="StatusProposalMissingName">
          <code>StatusProposalMissingName</code>
        </a>
      </td>
      <td>6</td>
      <td>The provided proposal does not have a short name.</td>
    </tr>
    <tr>
      <td>
        <a name="StatusProposalMissingDescription">
          <code>StatusProposalMissingDescription</code>
        </a>
      </td>
      <td>7</td>
      <td>The provided proposal does not have a description.</td>
    </tr>
    <tr>
      <td>
        <a name="StatusProposalNotFound">
          <code>StatusProposalNotFound</code>
        </a>
      </td>
      <td>8</td>
      <td>The requested proposal does not exist.</td>
    </tr>
    <tr>
      <td>
        <a name="StatusMaxMDsExceededPolicy">
          <code>StatusMaxMDsExceededPolicy</code>
        </a>
      </td>
      <td>9</td>
      <td>
        The submitted proposal has too many markdown files.  Limits can be obtained
        by issuing the <a href="#Policy">Policy</a> command.
      </td>
    </tr>
    <tr>
      <td>
        <a name="StatusMaxImagesExceededPolicy">
          <code>StatusMaxImagesExceededPolicy</code>
        </a>
      </td>
      <td>10</td>
      <td>
        The submitted proposal has too many images.  Limits can be obtained by
        issuing the <a href="#Policy">Policy</a> command.
      </td>
    </tr>
    <tr>
      <td>
        <a name="StatusMaxMDSizeExceededPolicy">
          <code>StatusMaxMDSizeExceededPolicy</code>
        </a>
      </td>
      <td>11</td>
      <td>
        The submitted proposal markdown is too large.  Limits can be obtained by
        issuing the <a href="#Policy">Policy</a> command.
      </td>
    </tr>
    <tr>
      <td>
        <a name="StatusMaxImageSizeExceededPolicy">
          <code>StatusMaxImageSizeExceededPolicy</code>
        </a>
      </td>
      <td>12</td>
      <td>
        The submitted proposal has one or more images that are too large.  Limits can
        be obtained by issuing the <a href="#Policy">Policy</a> command.
      </td>
    </tr>
    <tr>
      <td>
        <a name="StatusMalformedPassword">
          <code>StatusMalformedPassword</code>
        </a>
      </td>
      <td>13</td>
      <td>The provided password was malformed.</td>
    </tr>
    14 is comment not found // unhtml this please
  </tbody>
</table>

### Status codes

<table>
  <tbody>
    <tr>
      <th>Status</th>
      <th>Value</th>
      <th>Description</th>
    </tr>
    <tr>
      <td><a name="PropStatusInvalid"><code>PropStatusInvalid</code></a></td>
      <td>0</td>
      <td>An invalid status.  This shall be considered a bug.</td>
    </tr>
    <tr>
      <td>
        <a name="PropStatusNotFound">
          <code>PropStatusNotFound</code>
        </a>
      </td>
      <td>1</td>
      <td>The proposal was not found.</td>
    </tr>
    <tr>
      <td>
        <a name="PropStatusNotReviewed">
          <code>PropStatusNotReviewed</code>
        </a>
      </td>
      <td>2</td>
      <td>The proposal has not been reviewed by an admin.</td>
    </tr>
    <tr>
      <td>
        <a name="PropStatusCensored">
          <code>PropStatusCensored</code>
        </a>
      </td>
      <td>3</td>
      <td>The proposal has been censored by an admin.</td>
    </tr>
    <tr>
      <td>
        <a name="PropStatusPublic">
          <code>PropStatusPublic</code>
        </a>
      </td>
      <td>4</td>
      <td>The proposal has been published by an admin.</td>
    </tr>
  </tbody>
</table>

### Censorship record

<table>
  <tbody>
    <tr>
      <th></th>
      <th>Type</th>
      <th>Description</th>
    </tr>
    <tr>
      <td><code>token</code></td>
      <td>String</td>
      <td>
        The token is a 32 byte random number that was assigned to identify
        the submitted proposal.  This is the key to later retrieve
        the submitted proposal from the system.
      </td>
    </tr>
    <tr>
      <td><code>merkle</code></td>
      <td>String</td>
      <td>
        Merkle root of the proposal.  This is defined as the <b>sorted</b>
        digests of all files proposal files.  The client should cross
        verify this value.
      </td>
    </tr>
    <tr>
      <td><code>signature</code></td>
      <td>String</td>
      <td>
        Signature of merkle+token.  The token is appended to the merkle
        root and then signed.  The client should verify the signature.
      </td>
    </tr>
  </tbody>
</table>
