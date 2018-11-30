# politeiad API Specification

# v1

This document describes the REST API provided by a `politeiad` daemon.

`politeiad` provides a time-ordered cryptographically-accountable digital
commons where speech of various formats can be exchanged with a transparent
censorship mechanism.

**Methods**

- [`Identity`](#identity)
- [`New record`](#new-record)
- [`Get unvetted record`](#get-unvetted-record)
- [`Get vetted record`](#get-vetted-record)
- [`Set unvetted status`](#set-unvetted-status)
- [`Set vetted status`](#set-vetted-status)
- [`Update unvetted record`](#update-unvetted-record)
- [`Update vetted record`](#update-vetted-record)
- [`Update vetted metadata`](#update-vetted-metadata)
- [`Inventory`](#inventory)

**Error status codes**

- [`ErrorStatusInvalid`](#ErrorStatusInvalid)
- [`ErrorStatusInvalidRequestPayload`](#ErrorStatusInvalidRequestPayload)
- [`ErrorStatusInvalidChallenge`](#ErrorStatusInvalidChallenge)
- [`ErrorStatusInvalidFilename`](#ErrorStatusInvalidFilename)
- [`ErrorStatusInvalidFileDigest`](#ErrorStatusInvalidFileDigest)
- [`ErrorStatusInvalidBase64`](#ErrorStatusInvalidBase64)
- [`ErrorStatusInvalidMIMEType`](#ErrorStatusInvalidMIMEType)
- [`ErrorStatusUnsupportedMIMEType`](#ErrorStatusUnsupportedMIMEType)
- [`ErrorStatusInvalidRecordStatusTransition`](#ErrorStatusInvalidRecordStatusTransition)
- [`ErrorStatusEmpty`](#ErrorStatusEmpty)
- [`ErrorStatusInvalidMDID`](#ErrorStatusInvalidMDID)
- [`ErrorStatusDuplicateMDID`](#ErrorStatusDuplicateMDID)
- [`ErrorStatusDuplicateFilename`](#ErrorStatusDuplicateFilename)
- [`ErrorStatusFileNotFound`](#ErrorStatusFileNotFound)
- [`ErrorStatusNoChanges`](#ErrorStatusNoChanges)

**Record status codes**

- [`RecordStatusInvalid`](#RecordStatusInvalid)
- [`RecordStatusNotFound`](#RecordStatusNotFound)
- [`RecordStatusNotReviewed`](#RecordStatusNotReviewed)
- [`RecordStatusCensored`](#RecordStatusCensored)
- [`RecordStatusPublic`](#RecordStatusPublic)
- [`RecordStatusUnreviewedChanges`](#RecordStatusUnreviewedChanges)

## Methods

### `Identity`

Obtain `politeiad` Ed25519 public key. For more information go to
https://ed25519.cr.yp.to/

All `politeiad` commands are initiated by clients and shall contain a challenge
that shall be signed by the server.  The client challenge shall be a 32 byte
hex encoded array. Clients shall verify the challenge signature.

**Route**: `POST /v1/identity`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| challenge | string | 32 byte hex encoded array. | Yes |

**Results**:

| | Type | Description |
|-|-|-|
| response | string | hex encoded signature of challenge byte array. |
| publickey | string | Ed25519 public key that is used to verify all server side signatures. |

**Example**

Request:

```json
{
  "challenge":"808a6d4f02d91434f3b7e176f1cc8d0a2e90b47565ff1f0d722386b7785d3e3e"
}
```

Reply:

```json
{
  "response":"fa51baceaf08edb0e75aaf02d8a0180757c960650f3df63fc7fabe7b4677fe3cb07fabcdb700ed5aded5818cb92ba05f97a83fae606710f74deaeef238868406",
  "publickey":"8f627e9da14322626d7e81d789f7fcafd25f62235a95377f39cbc7293c4944ad"
}
```

### `New record`

Create a new record.

**Route**: `POST /v1/newrecord`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| challenge | string | 32 byte hex encoded array. | Yes |
| metadata | array of [`Metadata stream`](#metadata-stream) | Streams of non-provable metadata. | Yes |
| files | array of [`File`](#file) | Files that make up the provable record. | Yes |

**Results**:

| | Type | Description |
|-|-|-|
| response | string | hex encoded signature of challenge byte array. |
| censorshiprecord | [CensorshipRecord](#censorship-record) | A censorship record that provides the submitter with a method to extract the record and prove that he/she submitted it. |

**Example**

Request:

```json
{
  "challenge":"de0256b26ad723a979febf1d4b59c4dcd451946fcf16bea314a5286a45d2af3e",
  "metadata":
  [
    {
      "id":12,
      "payload":"{\"moo\":\"lala\"}"
    },
    {
      "id":2,
      "payload":"{\"foo\":\"bar\"}"
    }
  ],
  "files":
  [
    {
      "name":"a",
      "mime":"text/plain; charset=utf-8",
      "digest":"22e88c7d6da9b73fbb515ed6a8f6d133c680527a799e3069ca7ce346d90649b2",
      "payload":"bW9vCg=="
    }
  ]
}
```

Reply:

```json
{
  "response":"3d01eb4929c4d7bbe08cd139b872f3f2b626602340e7010335259b04e80564499acefbe7fec5b55203517c55e710f01c726820a428fdf7c9ab791ebba65acc03",
  "censorshiprecord":
  {
    "token":"d76e2f721957dfadee51c1edd6a478dcff6291a3b5b10e15557bbeddf11abe82",
    "merkle":"22e88c7d6da9b73fbb515ed6a8f6d133c680527a799e3069ca7ce346d90649b2",
    "signature":"6a1f539ad8c9098eb05732157b066df05a659d477864130cc0d74403c1253c40d60718b27786c36e8fd96cac1a8beac5c768c1423bfd65acc3e180276364840b"
  }
}
```

### `Get unvetted record`

Retrieve an unvetted record.

**Route**: `POST /v1/getunvetted`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| challenge | string | 32 byte hex encoded array. | Yes |
| token | string | Record identifier. | Yes |

**Results**:

| | Type | Description |
|-|-|-|
| response | string | hex encoded signature of challenge byte array. |
| record | [Record](#record) | Record, including metadata. |

**Example**

Request:

```json
{
  "challenge":"36a5c4d0574e8b963d7221a867eb3d629089b3b83b58e600aeb291b786743231",
  "token":"e2354df18ea005e409ae488a07c73d1648944ea07b350c1d0854f76d520855d4"
}
```

Reply:

```json
{
  "response":"914d8aa889b7a3fbfbbbe168f3ff8c502984efe40505b569abb11c0ce7665c2938eabc853cb77afa53f1d0db9ef588def0f65ff6d126407ae6a9b8bd3c08ee08",
  "record":
  {
    "status":2,
    "timestamp":1512761862,
    "censorshiprecord":
    {
      "token":"e2354df18ea005e409ae488a07c73d1648944ea07b350c1d0854f76d520855d4",
      "merkle":"22e88c7d6da9b73fbb515ed6a8f6d133c680527a799e3069ca7ce346d90649b2",
      "signature":"23a40823bc75bd984d47039b0ee4066fe750701aec26f0dceeae5882425b4ac09c8a0cf4a6b09ad0284fafbc6f142e8a80e7d97448ddd1ae321390bd7d91b305"
    },
    "metadata":
    [
      {
        "id":2,
	"payload":"{\"foo\":\"bar\"}"
      },{
        "id":12,
	"payload":"{\"moo\":\"lala\"}"
      }
    ],
    "files":
    [
      {
        "name":"a",
	"mime":"text/plain; charset=utf-8",
	"digest":"22e88c7d6da9b73fbb515ed6a8f6d133c680527a799e3069ca7ce346d90649b2",
	"payload":"bW9vCg=="
      }
    ]
  }
}
```

### `Get vetted record`

Retrieve a vetted record.

**Route**: `POST /v1/getvetted`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| challenge | string | 32 byte hex encoded array. | Yes |
| token | string | Record identifier. | Yes |
| version | string | Record version. | No |
**Results**:

| | Type | Description |
|-|-|-|
| response | string | hex encoded signature of challenge byte array. |
| record | [Record](#record) | Record, including metadata. |

**Example**

Request:

```json
{
  "challenge":"8a18531579091a9de89ba1f8d61878bd39540126950b4a668d19c2a57eea6acf",
  "token":"b468a8f7b1cc96031b7ba0f83c57c67f64e9247482f32be59baaa9f6631a2fea"
}
```

Reply:

```json
{
  "response":"f782a969a49cd5e779a748b8c3aa1be758d19f4af0631519e0a74d8cd26787a8d74ad359e738623985e16f64d2c1d5871273c85627519295afc4058703bd6508",
  "record":
  {
    "status":4,
    "timestamp":1513013590,
    "censorshiprecord":
    {
      "token":"b468a8f7b1cc96031b7ba0f83c57c67f64e9247482f32be59baaa9f6631a2fea",
      "merkle":"77ba3195336398cd9faa7bc8cefe2bbfbb2b4979fef92a400ce6e91e29ef22d2",
      "signature":"c94cd71ba065381ad1832d59b5b3d525213012e3a8ed29e8f15646ecaad1ce0109f88cdb343dde516d80c6b32ae69794d897ce6964a719347d61443483b35103"
    },
    "metadata":
    [
      {
        "id":2,
	"payload":"{\"foo\":\"bar\"}"},
	{"id":12,"payload":"{\"moo\":\"lala\"}"
      }
    ],
    "files":
    [
      {
        "name":"a",
	"mime":"text/plain; charset=utf-8",
	"digest":"22e88c7d6da9b73fbb515ed6a8f6d133c680527a799e3069ca7ce346d90649b2",
	"payload":"bW9vCg=="
      },
      {
        "name":"b",
	"mime":"text/plain; charset=utf-8",
	"digest":"12a31b5e662dfa0a572e9fc523eb703f9708de5e2d53aba74f8ebcebbdb706f7",
	"payload":"aWJsZWgK"
      }
    ]
  }
}
```

### `Set unvetted status`

Set unvetted status of a record.  There are only a few valid state transitions.
A record that public or unreviewed may be changed.  Changes must be vetted by
issuing a [`Set unvetted status`](#set-unvetted-status) call. Note that
individual updates will be visible once the changes are made public.

One can, optionally, send in metadata streams for update as well.  This can,
for example, be used to mark who made an update.

Censoring a record is a permanent action and once a recod is censored it can
not be modfied.

This command requires administrator privileges.

**Route**: `POST /v1/setunvettedstatus`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| challenge | string | 32 byte hex encoded array. | Yes |
| token | string | Record identifier. | Yes |
| status | number | New record status. | Yes |
| mdappend | array of [`MetadataStream`](#metadatastream) | Append payload to metadata stream(s). | No |
| mdoverwrite | array of [`MetadataStream`](#metadatastream) | Overwrite payload to metadata stream(s). | No |

**Results**:

| | Type | Description |
|-|-|-|
| response | string | hex encoded signature of challenge byte array. |
| status | number | New record status. |

**Example**

Request:

```json
{
  "challenge":"db30532986113a7f973a589700e4296c93b3d9662a07c778bcf1ef4011dceb90",
  "token":"1993f120323c4a4f89bf75cbd72e8eb728246e1e48292052abe8221e49588423",
  "status":3,
  "mdappend":
  [
    {
      "id":2,
      "payload":"{\"11foo\":\"11bar\"}"
    }
  ],
  "mdoverwrite":
  [
    {
      "id":12,"payload":"\"zap\""
    }
  ]
}
```

Reply:

```json
{
  "response":"a5cd683beec39c34ec7b01ad7c2c0c57757dbe7353f5b759ac6121755a5465b5edd157b0d198c8fdfa7d9960876dc4dfbd10dfb63acba93b8ba05d342668320d",
  "status":3
}
```

### `Set vetted status`

Set vetted status of a record.  The only state transition that is allowed is 
setting a record that is public to archived.  Changes must be vetted by
issuing a [`Set vetted status`](#set-vetted-status) call.

One can, optionally, send in metadata streams for update as well.  This can,
for example, be used to mark who made an update.

Marking a proposal as abanonded is a permanent action and once a record is
archived it can not be modified.

This command requires administrator privileges.

**Route**: `POST /v1/setvettedstatus`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| challenge | string | 32 byte hex encoded array. | Yes |
| token | string | Record identifier. | Yes |
| status | number | New record status. | Yes |
| mdappend | array of [`MetadataStream`](#metadatastream) | Append payload to metadata stream(s). | No |
| mdoverwrite | array of [`MetadataStream`](#metadatastream) | Overwrite payload to metadata stream(s). | No |

**Results**:

| | Type | Description |
|-|-|-|
| response | string | hex encoded signature of challenge byte array. |
| status | number | New record status. |

**Example**

Request:

```json
{
  "challenge":"db30532986113a7f973a589700e4296c93b3d9662a07c778bcf1ef4011dceb90",
  "token":"1993f120323c4a4f89bf75cbd72e8eb728246e1e48292052abe8221e49588423",
  "status":6,
  "mdappend":
  [
    {
      "id":2,
      "payload":"{\"11foo\":\"11bar\"}"
    }
  ],
  "mdoverwrite":
  [
    {
      "id":12,"payload":"\"zap\""
    }
  ]
}
```

Reply:

```json
{
  "response":"a5cd683beec39c34ec7b01ad7c2c0c57757dbe7353f5b759ac6121755a5465b5edd157b0d198c8fdfa7d9960876dc4dfbd10dfb63acba93b8ba05d342668320d",
  "status":6
}
```

### `Update unvetted record`

Update a unvetted record. This call enables a user to update a record by
adding/overwriting files, deleting files and append/overwrite metadata
records.  All changes will be recorded as changesets in the backend.

The returned censorship record will contain the newly calculated merkle root
of the entire record. It is the responsibility of the caller to keep track of
files that have been added or removed if they wish to independently verify 
the record.

Note that metadata streams are NOT part of the official record.  They exist for
the caller to be able to associate pertinent data to the record.  For example,
they can be used to store JSON encoded comments in a proposal system.

**Route**: `POST /v1/updateunvetted`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| challenge | string | 32 byte hex encoded array. | Yes |
| token | string | 32 byte record identifier. |
| mdappend | array of [`MetadataStream`](#metadatastream) | Append payload to metadata stream(s). | No |
| mdoverwrite | array of [`MetadataStream`](#metadatastream) | Overwrite payload to metadata stream(s). | No |
| filesdel | array of string | Filesnames to remove from record. | No |
| filesadd | array of [`File`](#file) | Files to add/overwrite in record. | No |

**Results**:

| | Type | Description |
|-|-|-|
| response | string | hex encoded signature of challenge byte array. |
| record | [Record](#record) | Record, including metadata. |

**Example**

Request:

```json
{
  "challenge":"3d41f60ffd17176e7b456e67a2fb712d3ff7a719edb45db11c87b124b9d9afc1",
  "token":"793766f3be00e093318b8f13e6e0e200be209d56b53263ce61c5f9fbb2309321",
  "mdappend":
  [
    {
      "id":12,
      "payload":"{\"foo\":\"bar\"}"
    }
  ],
  "mdoverwrite":null,
  "filesdel":
  [
    "a"
  ],
  "filesadd":
  [
    {
    "name":"b",
    "mime":"text/plain; charset=utf-8",
    "digest":"12a31b5e662dfa0a572e9fc523eb703f9708de5e2d53aba74f8ebcebbdb706f7",
    "payload":"aWJsZWgK"
    }
  ]
}
```

Reply:

```json
{
  "response":"f782a969a49cd5e779a748b8c3aa1be758d19f4af0631519e0a74d8cd26787a8d74ad359e738623985e16f64d2c1d5871273c85627519295afc4058703bd6508",
  "record":
  {
    "status":5,
    "timestamp":1513013590,
    "version": 1,
    "censorshiprecord":
    {
      "token":"793766f3be00e093318b8f13e6e0e200be209d56b53263ce61c5f9fbb2309321",
      "merkle":"77ba3195336398cd9faa7bc8cefe2bbfbb2b4979fef92a400ce6e91e29ef22d2",
      "signature":"c94cd71ba065381ad1832d59b5b3d525213012e3a8ed29e8f15646ecaad1ce0109f88cdb343dde516d80c6b32ae69794d897ce6964a719347d61443483b35103"
    },
    "metadata":
    [
      {
        "id":2,
        "payload":"{\"foo\":\"bar\"}"},
        {"id":12,"payload":"{\"moo\":\"lala\"}"
      }
    ],
    "files":
    [
      {
        "name":"b",
        "mime":"text/plain; charset=utf-8",
        "digest":"12a31b5e662dfa0a572e9fc523eb703f9708de5e2d53aba74f8ebcebbdb706f7",
        "payload":"aWJsZWgK"
      }
    ]
  }
}
```

### `Update vetted record`

Update a vetted record. This call enables a user to update a record by
adding/overwriting files, deleting files and append/overwrite metadata
records. All changes will be recorded as changesets in the backend.

A new version of the record will be generated and returned. The returned 
censorship record will contain the newly calculated merkle root of the 
entire record.

Note that metadata streams are NOT part of the official record.  They exist for
the caller to be able to associate pertinent data to the record.  For example,
they can be used to store JSON encoded comments in a proposal system.

**Route**: `POST /v1/updatevetted`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| challenge | string | 32 byte hex encoded array. | Yes |
| token | string | 32 byte record identifier. |
| mdappend | array of [`MetadataStream`](#metadatastream) | Append payload to metadata stream(s). | No |
| mdoverwrite | array of [`MetadataStream`](#metadatastream) | Overwrite payload to metadata stream(s). | No |
| filesdel | array of string | Filesnames to remove from record. | No |
| filesadd | array of [`File`](#file) | Files to add/overwrite in record. | No |

**Results**:

| | Type | Description |
|-|-|-|
| response | string | hex encoded signature of challenge byte array. |
| record | [Record](#record) | Record, including metadata. |

**Example**

Request:

```json
{
  "challenge":"3d41f60ffd17176e7b456e67a2fb712d3ff7a719edb45db11c87b124b9d9afc1",
  "token":"793766f3be00e093318b8f13e6e0e200be209d56b53263ce61c5f9fbb2309321",
  "mdappend":
  [
    {
      "id":12,
      "payload":"{\"foo\":\"bar\"}"
    }
  ],
  "mdoverwrite":null,
  "filesdel":
  [
    "a"
  ],
  "filesadd":
  [
    {
    "name":"b",
    "mime":"text/plain; charset=utf-8",
    "digest":"12a31b5e662dfa0a572e9fc523eb703f9708de5e2d53aba74f8ebcebbdb706f7",
    "payload":"aWJsZWgK"
    }
  ]
}
```

Reply:

```json
{
  "response":"f782a969a49cd5e779a748b8c3aa1be758d19f4af0631519e0a74d8cd26787a8d74ad359e738623985e16f64d2c1d5871273c85627519295afc4058703bd6508",
  "record":
  {
    "status":4,
    "timestamp":1513013590,
    "version": 2,
    "censorshiprecord":
    {
      "token":"793766f3be00e093318b8f13e6e0e200be209d56b53263ce61c5f9fbb2309321",
      "merkle":"77ba3195336398cd9faa7bc8cefe2bbfbb2b4979fef92a400ce6e91e29ef22d2",
      "signature":"c94cd71ba065381ad1832d59b5b3d525213012e3a8ed29e8f15646ecaad1ce0109f88cdb343dde516d80c6b32ae69794d897ce6964a719347d61443483b35103"
    },
    "metadata":
    [
      {
        "id":2,
        "payload":"{\"foo\":\"bar\"}"},
        {"id":12,"payload":"{\"moo\":\"lala\"}"
      }
    ],
    "files":
    [
      {
        "name":"b",
        "mime":"text/plain; charset=utf-8",
        "digest":"12a31b5e662dfa0a572e9fc523eb703f9708de5e2d53aba74f8ebcebbdb706f7",
        "payload":"aWJsZWgK"
      }
    ]
  }
}
```

### `Update vetted metadata`

Update a record's metadata.  This call enables a user to update a record's
metadata by appending/overwriting metadata records.

Note that metadata streams are NOT part of the official record.  They exist for
the caller to be able to associate pertinent data to the record.  For example,
they can be used to store JSON encoded comments in a proposal system.

The caller must ensure that unvetted metadata does not clash with the vetted
metadata update.  This will lead on undocumented errors.  The metadata streams
should therefore never be updated with multiple calls.  Pick a methodology and
stick with it for that stream.

This command requires administrator privileges.

**Route**: `POST /v1/updatevettedmd`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|
| challenge | string | 32 byte hex encoded array. | Yes |
| token | string | 32 byte record identifier. |
| mdappend | array of [`MetadataStream`](#metadatastream) | Append payload to metadata stream(s). | No |
| mdoverwrite | array of [`MetadataStream`](#metadatastream) | Overwrite payload to metadata stream(s). | No |

**Results**:

| | Type | Description |
|-|-|-|
| response | string | hex encoded signature of challenge byte array. |

**Example**

Request:

```json
{
  "challenge":"3d41f60ffd17176e7b456e67a2fb712d3ff7a719edb45db11c87b124b9d9afc1",
  "token":"793766f3be00e093318b8f13e6e0e200be209d56b53263ce61c5f9fbb2309321",
  "mdappend":
  [
    {
      "id":12,
      "payload":"{\"foo\":\"bar\"}"
    }
  ],
  "mdoverwrite":null,
}
```

Reply:

```json
{
  "response":"ee90b6bc26a899916d80dacef0bef1ba8238b94d9a00edbc04c69372c21faa96abbe3f6f91ece0879ca4616e713951380cdb7762e23c477708f4aba35c366b0c",
}
```

### `Inventory`

Retrieve all records.  This is a very expensive call.
This command requires administrator privileges.

**Route**: `POST /v1/inventory`

**Params**:

| Parameter | Type | Description | Required |
|-|-|-|-|

**Results**:

| | Type | Description |
|-|-|-|

**Example**

Request:

```json
```

Reply:

```json
```

### `Error status codes`

| Status | Value | Description |
|-|-|-|
| <a name="ErrorStatusInvalid">ErrorStatusInvalid</a>| 0 | An invalid status. This shall be considered a bug. |
| <a name="ErrorStatusInvalidRequestPayload">ErrorStatusInvalidRequestPayload</a>| 1 | Invalid requested payload. |
| <a name="ErrorStatusInvalidChallenge">ErrorStatusInvalidChallenge</a>| 2 | Invalid challenge. |
| <a name="ErrorStatusInvalidFilename">ErrorStatusInvalidFilename</a>| 3 | Invalid filename submitted in record. |
| <a name="ErrorStatusInvalidFileDigest">ErrorStatusInvalidFileDigest</a>| 4 | Invalid file digest. |
| <a name="ErrorStatusInvalidBase64">ErrorStatusInvalidBase64</a>| 5 | Payload not base64 encoded. |
| <a name="ErrorStatusInvalidMIMEType">ErrorStatusInvalidMIMEType</a>| 6 | Payload MIME type does not match. |
| <a name="ErrorStatusUnsupportedMIMEType">ErrorStatusUnsupportedMIMEType</a>| 7 | Unsuported MIME type. |
| <a name="ErrorStatusInvalidRecordStatusTransition">ErrorStatusInvalidRecordStatusTransition</a>| 8 | Invalid record status stransition. |
| <a name="ErrorStatusEmpty">ErrorStatusEmpty</a>| 9 | No files in record. |
| <a name="ErrorStatusInvalidMDID">ErrorStatusInvalidMDID</a>| 10 | Invalid metadata stream identifier. Possible values 0..15 |
| <a name="ErrorStatusDuplicateMDID">ErrorStatusDuplicateMDID</a>| 11 | Duplicate metadata stream identifier. |
| <a name="ErrorStatusDuplicateFilename">ErrorStatusDuplicateFilename</a>| 12 | Duplicate filename. |
| <a name="ErrorStatusFileNotFound">ErrorStatusFileNotFound</a>| 13 | File does not exist. |
| <a name="ErrorStatusNoChanges">ErrorStatusNoChanges</a>| 14 | File does not exist. |

### `Record status codes`

| Status | Value | Description |
|-|-|-|
| <a name="RecordStatusInvalid">RecordStatusInvalid</a>| 0 | An invalid status. This shall be considered a bug. |
| <a name="RecordStatusNotFound">RecordStatusNotFound</a>| 1 | Record not found. |
| <a name="RecordStatusNotReviewed">RecordStatusNotReviewed</a>| 2 | Record not reviewed. |
| <a name="RecordStatusCensored">RecordStatusCensored</a>| 3 | Record censored. |
| <a name="RecordStatusPublic">RecordStatusPublic</a>| 4 | Record published. |
| <a name="RecordStatusUnreviewedChanges">RecordStatusUnreviewedChanges</a>| 4 | Record s published but it has unpublished changes. |

### `File`

| | Type | Description |
|-|-|-|
| name | string | Name is the suggested filename. There should be no filenames that are overlapping and the name shall be validated before being used. |
| mime | string | MIME type of the payload. Currently the system only supports md and png files. The server shall reject invalid MIME types. |
| digest | string | Digest is a SHA256 digest of the payload. The digest shall be verified by politeiad. |
| payload | string | Payload is the actual file content. It shall be base64 encoded. |

### `Metadata stream`
| | Type | Description |
|-|-|-|
| id | uint64 | ID of the metadata stream. Currently politeiad supports 16 (0..15) streams per record. |
| payload | string | Running metadata records. These are not verified or handled by the server.  They are simply stored alongside the record. |

### `Censorship record`

| | Type | Description |
|-|-|-|
| token | string | The token is a 32 byte random number that was assigned to identify the submitted record. This is the key to later retrieve the submitted record from the system. |
| merkle | string | Merkle root of the record. This is defined as the sorted digests of all files record files. The client should cross verify this value. |
| signature | string | Signature of byte array representations of merkle+token. The token byte array is appended to the merkle root byte array and then signed. The client should verify the signature. |

### `Record`

| | Type | Description |
|-|-|-|
| status | [`Record status`](#record-status) | Current status. |
| timestamp | int64 | Last update. |
| censorshiprecord | [`Censorship record`](#censorship-record) | Censorship record. |
| version | string | Version of this record |
| metadata | [`Metadata stream`](#metadata-stream) | Metadata streams. |
| files | [`Files`](#files) | Files. |
