# Comments API Specification

This document describes the comments plugin API.

**Routes**

- [`Policy`](#policy)
- [`New`](#new)
- [`Edit`](#edit)
- [`Vote`](#vote)
- [`Del`](#del)
- [`Count`](#count)
- [`Comments`](#comments)
- [`Votes`](#votes)
- [`Timestamps`](#timestamps)


**Error Status Codes**

- [`ErrorCodeInvalid`](#ErrorCodeInvalid)
- [`ErrorCodeInputInvalid`](#ErrorCodeInputInvalid)
- [`ErrorCodeUnauthorized`](#ErrorCodeUnauthorized)
- [`ErrorCodePublicKeyInvalid`](#ErrorCodePublicKeyInvalid)
- [`ErrorCodeSignatureInvalid`](#ErrorCodeSignatureInvalid)
- [`ErrorCodeRecordStateInvalid`](#ErrorCodeRecordStateInvalid)
- [`ErrorCodeTokenInvalid`](#ErrorCodeTokenInvalid)
- [`ErrorCodeRecordLocked`](#ErrorCodeRecordLocked)
- [`ErrorCodePageSizeExceeded`](#ErrorCodePageSizeExceeded)
- [`ErrorCodeRecordStateInvalid`](#ErrorCodeDuplicatePayload)

## HTTP status codes and errors

All routes, unless otherwise specified, shall return `200 OK` when successful,
`400 Bad Request` when an error has occurred due to user input, or `500
Internal Server Error` when an unexpected server error has occurred. The format
of errors is as follows:

**`4xx` errors**

| Field | Type | Description |
|-|-|-|
| errorcode | number | One of the [error codes](#error-codes) |
| errorcontext | String | This field is used to provide additional information for certain errors. |

**`5xx` errors**

| Field | Type | Description |
|-|-|-|
| errorcode | number | An error code that can be used to track down the internal server error that occurred; it should be reported to Politeia administrators. |

## Routes

### `Policy` 

Retrieve the policy settings for the comments API.

**Route**: `POST /policy`

**Params**: none

**Reply**:

| Field | Type | Description |
|-|-|-|
| lengthmax | number | Maximum number of characters that are allowed in a comment. |
| votechangesmax | number | Maximum number of times a user can change their vote on a comment. |
| allowextradata | bool |  Determines whether posting extra data along with the comment is allowed. |
| votespagesize | number | Maximum number of comment votes that can be returned at any one time. |
| timestampspagesize | number | Maximum number of comment timestamps that can be requested at any one time. |
| countpagesize | number | Maximum number of comment counts that can be requested at any one time. |
| allowedits | bool | Determines whether comment edits are temporarily allowed during the  timeframe set by editperiod. |
| editperiod | number | Maximum amount of time, in seconds, since the submission of a comment where it's still editable. |

### `New`

Creates a new comment.

**Route**: `POST /new`

**Params**: 

| Parameter | Type | Description | Required |
|-|-|-|-|
| state | RecordStateT | Record state. | Yes |
| token | string | Record token. | Yes |
| parentid | number | Parent comment ID. | No |
| comment | string | Comment body. | Yes |
| publickey | string | User public key used for signature. | Yes |
| signature | string | Client signature. | Yes |
| extradata | string | Extra data - allows creating different types of comments. | No |
| extradatahint | string | Extra data hint - used to decode the extra data. | No |

**Reply**:

| Field | Type | Description |
|-|-|-|
| comment | [`Comment`](#comment) | Submitted comment. |
