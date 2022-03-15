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
- [`ErrorCodeRecordNotFound`](#ErrorCodeRecordNotFound)
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
| state | [`RecordStateT`](#recordstatet) | Record state. | Yes |
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

### `Edit`

Edits an existing comment.

**Route**: `POST /edit`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| state | [`RecordStateT`](#recordstatet) | Record state. | Yes |
| token | string | Record token. | Yes |
| parentid | number | Parent comment ID. | No |
| commentid | number | Comment ID. | Yes |
| comment | string | Comment body. | Yes |
| publickey | string | User public key used for signature. | Yes |
| signature | string | Client signature. | Yes |
| extradata | string | Extra data - allows creating different types of comments. | No |
| extradatahint | string | Extra data hint - used to decode the extra data. | No |

**Reply**:

| Field | Type | Description |
|-|-|-|
| comment | [`Comment`](#comment) | Editted comment. |

### `Vote`

Casts a comment vote (upvote or downvote).

**Route**: `POST /vote`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| state | [`RecordStateT`](#recordstatet) | Record state. | Yes |
| token | string | Record token. | Yes |
| commentid | number | Comment ID. | Yes |
| vote | VoteT | Comment vote type. | Yes |
| publickey | string | User public key used for signature. | Yes |
| signature | string | Client signature. | Yes |

**Reply**:

| Field | Type | Description |
|-|-|-|
| downvotes | number | Total downvotes on comment. |
| upvotes | number | Total upvotes on comment. |
| timestamp | number | Received UNIX timestamp. |
| receipt | string | Server signature of client signature. |

### `Del`

Permanently deletes the provided comment. Only admins can delete comments. 
A reason must be given for the deletion.

**Route**: `POST /del`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| state | [`RecordStateT`](#recordstatet) | Record state. | Yes |
| token | string | Record token. | Yes |
| commentid | number | Comment ID. | Yes |
| reason | string | Reason for deletion. | Yes |
| publickey | string | User public key used for signature. | Yes |
| signature | string | Client signature. | Yes |

**Reply**:

| Field | Type | Description |
|-|-|-|
| comment | [`Comment`](#comment) | Deleted comment. |

### `Count`

Requests the number of comments on that have been made on the given records. 
If a record is not found for a token then it will not be included in the
returned map.

**Route**: `POST /count`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| tokens | []string | Record tokens. | Yes |

**Reply**:

| Field | Type | Description |
|-|-|-|
| counts | map[string]number | Comment counts map. map[token]=>count |

### `Comments`

Requests a record's comments.

**Route**: `POST /comments`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| token | string | Record token. | Yes |

**Reply**:

| Field | Type | Description |
|-|-|-|
| comments | [][`Comment`](#comment) | Record comments. |

### `Votes`

Retrieves the record's comment votes that meet the provided filtering 
criteria. If no filtering criteria is provided then it rerieves all comment
votes. This command is paginated, if no page is provided, then the first page 
is returned. If the requested page does not exist an empty page is returned.

**Route**: `POST /votes`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| token | string | Record token. | Yes |
| userid | string | User ID. | Yes |
| page | number | Requested page. | Yes |

**Reply**:

| Field | Type | Description |
|-|-|-|
| votes | [][`CommentVote`](#commentvote) | Comment votes. |

### `Timestamps`

Requests the timestamps for the comments of a record.

**Route**: `POST /timestamps`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| token | string | Record token. | Yes |
| commentids | []number | Comment IDs. | Yes |

**Reply**:

| Field | Type | Description |
|-|-|-|
| comments | map[number][`CommentTimestamp`](#commenttimestamp) | Comment timestamps. |

### `Error codes`

| Error | Value | Description |
|-|-|-|
| ErrorCodeInvalid | 0 | Error invalid. |
| ErrorCodeInputInvalid | 1 | Input invalid. |
| ErrorCodeUnauthorized | 2 | Unauthorized. |
| ErrorCodePublicKeyInvalid | 3 | Public key invalid. |
| ErrorCodeSignatureInvalid | 4 | Signature invalid. |
| ErrorCodeRecordStateInvalid | 5 | Record state invalid. |
| ErrorCodeTokenInvalid | 6 | Token invalid. |
| ErrorCodeRecordNotFound | 7 | Record not found. |
| ErrorCodeRecordLocked | 8 | Record is locked. |
| ErrorCodePageSizeExceeded | 9 | Page size exceeded. |
| ErrorCodeDuplicatePayload | 10 | Duplicate payload. |


XXX structs here XXX
