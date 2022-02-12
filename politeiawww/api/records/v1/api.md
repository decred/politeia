# Records API Specification

This document describes the records plugin API.

**Routes**

- [`Policy`](#policy)
- [`New`](#new)
- [`Edit`](#edit)
- [`SetStatus`](#set-status)
- [`Details`](#details)
- [`Timestamps`](#timestamps)
- [`Records`](#records)
- [`Inventory`](#inventory)
- [`InventoryOrdered`](#inventory-ordered)
- [`UserRecords`](#user-records)

**Error Status Codes**

- [`ErrorCodeInvalid`](#ErrorCodeInvalid)
- [`ErrorCodeInputInvalid`](#ErrorCodeInputInvalid)
- [`ErrorCodeFilesEmpty`](#ErrorCodeFilesEmpty)
- [`ErrorCodeFileNameInvalid`](#ErrorCodeFileNameInvalid)
- [`ErrorCodeFileNameDuplicate`](#ErrorCodeFileNameDuplicate)
- [`ErrorCodeFileMIMETypeInvalid`](#ErrorCodeFileMIMETypeInvalid)
- [`ErrorCodeFileMIMETypeUnsupported`](#ErrorCodeFileMIMETypeUnsupported)
- [`ErrorCodeFileDigestInvalid`](#ErrorCodeFileDigestInvalid)
- [`ErrorCodeFilePayloadInvalid`](#ErrorCodeFilePayloadInvalid)
- [`ErrorCodeMetadataStreamIDInvalid`](#ErrorCodeMetadataStreamIDInvalid)
- [`ErrorCodePublicKeyInvalid`](#ErrorCodePublicKeyInvalid)
- [`ErrorCodeSignatureInvalid`](#ErrorCodeSignatureInvalid)
- [`ErrorCodeRecordTokenInvalid`](#ErrorCodeRecordTokenInvalid)
- [`ErrorCodeRecordNotFound`](#ErrorCodeRecordNotFound)
- [`ErrorCodeRecordLocked`](#ErrorCodeRecordLocked)
- [`ErrorCodeNoRecordChanges`](#ErrorCodeNoRecordChanges)
- [`ErrorCodeRecordStateInvalid`](#ErrorCodeRecordStateInvalid)
- [`ErrorCodeRecordStatusInvalid`](#ErrorCodeRecordStatusInvalid)
- [`ErrorCodeStatusChangeInvalid`](#ErrorCodeStatusChangeInvalid)
- [`ErrorCodeStatusReasonNotFound`](#ErrorCodeStatusReasonNotFound)
- [`ErrorCodePageSizeExceeded`](#ErrorCodePageSizeExceeded)

## HTTP status codes and errors

All routes, unless otherwise specified, shall return `200 OK` when successful,
`400 Bad Request` when an error has occurred due to user input, or `500
Internal Server Error` when an unexpected server error has occurred. The format
of errors is as follows:

**`4xx` errors**

| | Type | Description |
|-|-|-|
| errorcode | number | One of the [error codes](#error-codes) |
| errorcontext | String | This field is used to provide additional information for certain errors. |

**`5xx` errors**

| | Type | Description |
|-|-|-|
| errorcode | number | An error code that can be used to track down the internal server error that occurred; it should be reported to Politeia administrators. |

## Routes

### `Policy` 

Retrieve the policy settings for the records API.

**Route**: `POST /policy`

**Params**: none

**Reply**:

| | Type | Description |
|-|-|-|
| recordspagesize | number | Maximum number of records that can be requested in a /records request. |
| inventorypagesize | number | Number of tokens that will be returned per page for all /inventory requests. |

