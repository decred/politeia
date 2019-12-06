# politeiawww API Specification

# v2

This document describes the v2 REST API provided by a `politeiawww` server.
The `politeiawww` server is the web server backend that interacts with clients
using a JSON REST API.

**Vote Routes**

- [`Start vote`](#start-vote)

### `Start vote`

Start the voting period on the given proposal.


Signature is a signature of the hex encoded SHA256 digest of the JSON encoded
v2 Vote struct.

**Route:** `POST /v1/proposals/startvote`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| publickey | string | Public key used to sign the vote | Yes |
| vote | Vote | Vote details | Yes |
| signature | string | Signature of the Vote digest | Yes |

**Results (StartVoteReply):**

| | Type | Description |
| - | - | - |
| startblockheight | uint32 | Start block height of the vote |
| startblockhash | string | Start block hash of the vote |
| endblockheight | uint32 | End block height of the vote |
| eligibletickets | []string | All ticket hashes that are eligible to vote |

**Vote:**

| | Type | Description |
| - | - | - |
| token | string | Censorship token |
| type | int | Type of proposal vote | 
| mask | uint64 | Mask for valid vote bits |
| duration | uint32 | Duration of the vote in blocks |
| quorumpercentage | uint32 | Percent of eligible votes required for a quorum |
| pass percentage | uint32 | Percent of total votes required for the proposal to considered approved | 
| options | []VoteOption | Vote options |

**VoteOption:**

| | Type | Description |
| - | - | - |
| Id | string | Single unique word that identifies this option, e.g. "yes" |
| Description | string | Human readable description of this option |
| Bits | uint64 | Bits that make up this choice, e.g. 0x01 |

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusInvalidPropVoteBits`](#ErrorStatusInvalidPropVoteBits)
- [`ErrorStatusInvalidPropVoteParams`](#ErrorStatusInvalidPropVoteParams)
- [`ErrorStatusInvalidSigningKey`](#ErrorStatusInvalidSigningKey)
- [`ErrorStatusInvalidSignature`](#ErrorStatusInvalidSignature)
- [`ErrorStatusProposalNotFound`](#ErrorStatusProposalNotFound)
- [`ErrorStatusWrongStatus`](#ErrorStatusWrongStatus)
- [`ErrorStatusWrongVoteStatus`](#ErrorStatusWrongVoteStatus)

**Example**

Request:

``` json
{
  "publickey": "d64d80c36441255e41fc1e7b6cd30259ff9a2b1276c32c7de1b7a832dff7f2c6",
  "vote": {
    "token": "127ea26cf994dabc27e115da0eb90a5657590e2ccc4e7c23c7f80c6fe4afaa59",
    "type": 1,
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
  "startblockheight": 282899,
  "startblockhash":"00000000017236b62ff1ce136328e6fb4bcd171801a281ce0a662e63cbc4c4fa",
  "endblockheight": 284915,
  "eligibletickets":[
    "000011e329fe0359ea1d2070d927c93971232c1118502dddf0b7f1014bf38d97",
    "0004b0f8b2883a2150749b2c8ba05652b02220e98895999fd96df790384888f9",
    "00107166c5fc5c322ecda3748a1896f4a2de6672aae25014123d2cedc83e8f42",
    "002272cf4788c3f726c30472f9c97d2ce66b997b5762ff4df6a05c4761272413"
  ]
}
```

Note: eligibletickets is abbreviated for readability.
