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

Retrieve the policy settings for the records API.

**Route**: `POST /policy`

**Params**: none

**Reply**:

| Field | Type | Description |
|-|-|-|
| recordspagesize | number | Maximum number of records that can be requested in a /records request. |
| inventorypagesize | number | Number of tokens that will be returned per page for all /inventory requests. |

### `New`

Submit a new record.

**Route**: `POST /new`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| files | [][`File`](#file) | Record files. | Yes |
| publickey | string | Signing user public key. | Yes |
| signature | string | Client signature of the record merkle root. The merkle root is the ordered merkle root of all record Files. | Yes |

**Reply**:

| Field | Type | Description |
|-|-|-|
| record | [`Record`](#record) | Submitted record. |

### `Edit`

Edit an existing record.

**Route**: `POST /edit`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| token | string | Existing record token. | Yes |
| files | [][`File`](#file) | Record files. | Yes |
| publickey | string | Signing user public key. | Yes |
| signature | string | Client signature of the record merkle root. The merkle root is the ordered merkle root of all record Files. | Yes |

**Reply**:

| Field | Type | Description |
|-|-|-|
| record | [`Record`](#record) | Submitted record. |

### `Set Status`

Set the status of a record. Some status changes require a reason to be included.

**Route**: `POST /setstatus`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| token | string | Record token. | Yes |
| version | number | Record version. | Yes |
| status | [`RecordStatusT`](#record-statuses) | Record's new status. | Yes |
| reason | string | Status change reason. | Required for some statuses |
| publickey | string | Signing user public key. | Yes |
| signature | string | Client signature of the Token+Version+Status+Reason. | Yes |

**Reply**:

| Field | Type | Description |
|-|-|-|
| record | [`Record`](#record) | Record after status change. |

### `Details`

Retrieve the details of a record. The full record will be returned.
If no version is specified then the most recent version will be returned.

**Route**: `POST /details`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| token | string | Record token. | Yes |
| version | number | Record version. | Yes |

**Reply**:

| Field | Type | Description |
|-|-|-|
| record | [`Record`](#record) | Record after status change. |

### `Timestamps`

Retrieve the timestamps for a specific record version. If the
version is omitted, the timestamps for the most recent version will be
returned.

**Route**: `POST /timestamps`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| token | string | Record token. | Yes |
| version | number | Record version. | Yes |

**Reply**:

| Field | Type | Description |
|-|-|-|
| recordmetadata | [`Timestamp`](#timestamp) | Record metadata timestamp. |
| metadata | map[string]map[number][`Timestamp`](#timestamp) | Map of metadata streams timestamps. map[pluginID]map[streamID]timestamp. |
| files | map[string][`Timestamp`](#timestamp) | Map of record files timestamps. map[filename]timestamp. |

### `Records`

Retrieve a batch of records. This route should be used when the
client only requires select content from the record. The Details command
should be used when the full record content is required. Unvetted record
files are only returned to admins and the author. Any tokens that did not
correspond to a record will not be included in the reply.

**Note**: partial record's merkle root is not verifiable - when generating
the record's merkle all files must be present.

**Route**: `POST /records`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| requests | [][`RecordRequest`](#record-request) | Select content from a record. | Yes |

**Reply**:

| Field | Type | Description |
|-|-|-|
| records | map[string][`Record`](#record) | Map of requested records. |

### `Inventory`

Retrieve the tokens of the records in the inventory, categorized
by record state and record status. The tokens are ordered by the timestamp
of their most recent status change, sorted from newest to oldest.

The state, status, and page arguments can be provided to request a specific
page of record tokens.

If no status is provided then a page of tokens for all statuses are
returned. The state and page arguments will be ignored.

Unvetted record tokens will only be returned to admins.

**Route**: `POST /inventory`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| state | [`RecordStateT`](#record-states) | Record state. | No |
| status | [`RecordStatusT`](#record-statuses) | Record status. | No |
| page | number | Requested page. | No |

**Reply**:

| Field | Type | Description |
|-|-|-|
| unvetted | map[string][]string | Map of unvetted records tokens. |
| vetted | map[string][]string | Map of vetted records tokens. |

### `Inventory Ordered`

Retrieve a page of record tokens ordered by the timestamp
of their most recent status change from newest to oldest. The reply will
include tokens for all record statuses. Unvetted tokens will only be
returned to admins.

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| state | [`RecordStateT`](#record-states) | Record state. | Yes |
| page | number | Requested page. | Yes |

**Reply**:

| Field | Type | Description |
|-|-|-|
| tokens | []string | Page of tokens. |

### `User Records`

Retrieve the tokens of all records submitted by a user.
Unvetted record tokens are only returned to admins and the record author.

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| userid | string | User ID. | Yes |

**Reply**:

| Field | Type | Description |
|-|-|-|
| unvetted | []string | User's unvetted records. |
| vetted | []string | User's vetted records. |

### `Error codes`

| Error | Value | Description |
|-|-|-|
| ErrorCodeInvalid | 0 | Error invalid. |
| ErrorCodeInputInvalid | 1 | Input invalid. |
| ErrorCodeFilesEmpty | 2 | Files are empty. |
| ErrorCodeFileNameInvalid | 3 | File name invalid. |
| ErrorCodeFileNameDuplicate | 4 | File name duplicate. |
| ErrorCodeFileMIMETypeInvalid | 5 | File MIME type invalid. |
| ErrorCodeFileMIMETypeUnsupported | 6 | File MIME type unsupported. |
| ErrorCodeFileDigestInvalid | 7 | File digest invalid. |
| ErrorCodeFilePayloadInvalid | 8 | File payload invalid. |
| ErrorCodeMetadataStreamIDInvalid | 9 | Metadata stream ID invalid. |
| ErrorCodePublicKeyInvalid | 10 | Public key invalid. |
| ErrorCodeSignatureInvalid | 11 | Signature invalid. |
| ErrorCodeRecordTokenInvalid | 12 | Record token invalid. |
| ErrorCodeRecordNotFound | 14 | Record not found. |
| ErrorCodeRecordLocked | 14 | Record locked. |
| ErrorCodeNoRecordChanges | 15 | No record changes. |
| ErrorCodeRecordStateInvalid | 16 | Record state invalid. |
| ErrorCodeRecordStatusInvalid | 17 | Record status invalid. |
| ErrorCodeStatusChangeInvalid | 18 | Status change invalid. |
| ErrorCodeStatusReasonNotFound | 19 | Status reason not found. |
| ErrorCodePageSizeExceeded | 20 | Page size exceeded. |

### `Record`

Represents a record and all of its content.

| Field | Type | Description |
|-|-|-|
| state | [`RecordStateT`](#record-states) | Record state. |
| status | [`RecordStatusT`](#record-statuses) | Record status. |
| version | number | Record version. |
| timestamp | number | Last update. |
| username | string | Author username. |
| metadata | [][`MetadataStream`](#metadata-stream) | Metadata streams. |
| files | [][`File`](#file) | User submitted files. |
| censorshiprecord | [`CensorshipRecord`](#censorship-record) | Contains cryptographic proof that a record was accepted for review by the server. The proof is verifiable by the client. |

### `Record states`

| State | Value | Description |
|-|-|-|
| RecordStateInvalid | 0 | Invalid. |
| RecordStateUnvetted | 1 | Unvetted. |
| RecordStateVetted | 2 | Vetted. |

### `Record statuses`

| Status | Value | Description |
|-|-|-|
| RecordStatusInvalid | 0 | Invalid. |
| RecordStatusUnreviewed | 1 | Unreviewed. |
| RecordStatusReviewed | 2 | Reviewed. |
| RecordStatusPublic | 2 | Public. |
| RecordStatusCensored | 3 | Cesnored. |
| RecordStatusArchived | 3 | Archived. |

### `Metadata stream`

Describes a record metadata stream.

| Field | Type | Description |
|-|-|-|
| pluginid | string | Plugin ID. |
| streamid | number | Stream ID. |
| payload | string | JSON encoded payload. |

### `File`

Describes an individual file that is part of the record.

| Field | Type | Description |
|-|-|-|
| name | string | File name. |
| mime | string | MIME type. |
| digest | string | SHA256 digest of unencoded payload. |
| payload | string | File content, base64 encoded. |

### `Censorship record`

Contains cryptographic proof that a record was accepted for
review by the server. The proof is verifiable by the client.

| Field | Type | Description |
|-|-|-|
| token | string | Random censorship token that is generated by the server. It serves as a unique identifier for the record. |
| merkle | string | Ordered merkle root of all files in the record. |
| signature | string | Server signature of the Merkle+Token. |

### `Timestamp`

Contains all of the data required to verify that a piece of 
record data was timestamped onto the decred blockchain.

All digests are hex encoded SHA256 digests. The merkle root can be found
in the OP_RETURN of the specified DCR transaction.

TxID, MerkleRoot, and Proofs will only be populated once the merkle root
has been included in a DCR tx and the tx has 6 confirmations. The Data
field will not be populated if the data has been censored.

| Field | Type | Description |
|-|-|-|
| data | string | Json encoded. |
| digest | string | Timestamped digest. |
| txid | string | Transaction ID. |
| merkleroot | string | Merkle root. |
| proofs | [][`Proof`](#proof) | Timestamp proofs. |

### `Proof`

Contains an inclusion proof for the digest in the merkle root. All
digests are hex encoded SHA256 digests.

| Field | Type | Description |
|-|-|-|
| type | string | Proof type. |
| digest | string | Timestamped digest. |
| merkleroot | string | Merkle root. |
| merklepath | string | Merkle path. |
| extradata| string | Json encoded extra data, used by certain types of proofs to include additional data that is required to validate the proof. |

