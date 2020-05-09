# politeiawww API Specification

# v2

This document describes the v2 REST API provided by a `politeiawww` server.
The `politeiawww` server is the web server backend that interacts with clients
using a JSON REST API.

**Vote Routes**

- [`Start vote`](#start-vote)
- [`Start vote runoff`](#start-vote-runoff)
- [`Vote details`](#vote-details)

### `Start vote`

Start the voting period on the given proposal.

Signature is a signature of the hex encoded SHA256 digest of the JSON encoded
v2 Vote struct.

Differences between v1 and v2 StartVote:
* Signature has been updated to be a signature of the Vote hash. It was
  previously a signature of just the proposal token.
* Vote has been updated. See the Vote comment below for more details.

Differences between v1 and v2 Vote:
* Added the "version" field that specifies the version of the proposal that is
  being voted on. This was added so that the proposal version is explicitly
  included in the StartVote signature.
* Added the "type" field that specifies the vote type.

Differences between v1 and v2 StartVoteReply:
* StartBlockHeight was changed from a string to a uint32.
* EndBlockHeight was changed from a string to a uint32. It was also renamed
  from EndHeight to EndBlockHeight to be consistent with StartBlockHeight.

**Route:** `POST /v2/vote/start`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| publickey | string | Public key used to sign the vote | Yes |
| vote | [`Vote`](#vote) | Vote details | Yes |
| signature | string | Signature of the Vote digest | Yes |

**Results (StartVoteReply):**

| | Type | Description |
| - | - | - |
| startblockheight | number | Start block height of the vote |
| startblockhash | string | Start block hash of the vote |
| endblockheight | number | End block height of the vote |
| eligibletickets | []string | All ticket hashes that are eligible to vote |

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusInvalidCensorshipToken`](#ErrorStatusInvalidCensorshipToken)
- [`ErrorStatusProposalNotFound`](#ErrorStatusProposalNotFound)
- [`ErrorStatusInvalidPropVoteBits`](#ErrorStatusInvalidPropVoteBits)
- [`ErrorStatusInvalidVoteOptions`](#ErrorStatusInvalidVoteOptions)
- [`ErrorStatusInvalidPropVoteParams`](#ErrorStatusInvalidPropVoteParams)
- [`ErrorStatusInvalidSigningKey`](#ErrorStatusInvalidSigningKey)
- [`ErrorStatusInvalidSignature`](#ErrorStatusInvalidSignature)
- [`ErrorStatusInvalidProposalVersion`](#ErrorStatusInvalidProposalVersion)
- [`ErrorStatusWrongStatus`](#ErrorStatusWrongStatus)
- [`ErrorStatusWrongVoteStatus`](#ErrorStatusWrongVoteStatus)
- [`ErrorStatusInvalidVoteType`] (#ErrorStatusInvalidVoteType)
- [`ErrorStatusWrongProposalType`](#ErrorStatusWrongProposalType)
- [`ErrorStatusInvalidLinkBy`](#ErrorStatusInvalidLinkBy)

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


### `Start vote runoff`
Start the runoff voting process on all public, non-abandoned RFP submissions
for the provided RFP token.

`AuthorizeVotes` must contain a vote authorization for each RFP submission that
is participating in the runoff vote. Unlike standard votes, these vote
authorizations are not signed by the submission author. They are signed by the
admin starting the runoff vote.

StartVotes must contain a StartVote for each RFP submission that is
participating in the runoff vote. The runoff vote can only be started once the
RFP proposal itself has been approved by a vote and once the LinkBy submission
deadline has expired. Once the LinkBy deadline has expired, the runoff vote can
be started at any point by an admin. It is not required that RFP submission
authors authorize the start of the vote.

**Route:** `POST /v2/vote/startrunoff`

**Params:**

| Parameter | Type | Description | Required |
|-|-|-|-|
| token | string | RFP proposal censorship token | Yes |
| authorizevotes | [][`AuthorizeVote`](#authorize-vote) | Authorize votes for rfp submissions | Yes |
| startvotes | [][`StartVote`](#start-vote) | Start votes for rfp submissions | Yes |

**Results (StartVoteRunoffReply):**

| | Type | Description |
| - | - | - |
| startblockheight | number | Start block height of the vote |
| startblockhash | string | Start block hash of the vote |
| endblockheight | number | End block height of the vote |
| eligibletickets | []string | All ticket hashes that are eligible to vote |

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusInvalidRunoffVote`](#ErrorStatusInvalidRunoffVote)
- [`ErrorStatusInvalidCensorshipToken`](#ErrorStatusInvalidCensorshipToken)
- [`ErrorStatusProposalNotFound`](#ErrorStatusProposalNotFound)
- [`ErrorStatusInvalidSigningKey`](#ErrorStatusInvalidSigningKey)
- [`ErrorStatusInvalidSignature`](#ErrorStatusInvalidSignature)
- [`ErrorStatusWrongStatus`](#ErrorStatusWrongStatus)
- [`ErrorStatusWrongVoteStatus`](#ErrorStatusWrongVoteStatus)
- [`ErrorStatusInvalidAuthVoteAction`](#ErrorStatusInvalidAuthVoteAction)
- [`ErrorStatusInvalidPropVoteBits`](#ErrorStatusInvalidPropVoteBits)
- [`ErrorStatusInvalidVoteOptions`](#ErrorStatusInvalidVoteOptions)
- [`ErrorStatusInvalidPropVoteParams`](#ErrorStatusInvalidPropVoteParams)
- [`ErrorStatusInvalidProposalVersion`](#ErrorStatusInvalidProposalVersion)
- [`ErrorStatusInvalidVoteType`] (#ErrorStatusInvalidVoteType)
- [`ErrorStatusWrongProposalType`](#ErrorStatusWrongProposalType)
- [`ErrorStatusLinkByDeadlineNotMet`](#ErrorStatusLinkByDeadlineNotMet)
- [`ErrorStatusNoLinkedProposals`](#ErrorStatusNoLinkedProposals)

**Example**

Request:

``` json
{
  "token": "b1052a4e099aa3b58edb4ad174fee88bc2ef52eb5d052b97ca062f043233a23b",
  "authorizevote": [
    {
      "token": "6ec6c28c350013873e15a37c16ffcea90dd08043ed55c44194008e167527999a",
      "action": "authorize",
      "publickey": "d8fa97b2ce42fb279938b9918b3bf5a7fb68ba6a3296159f237be27cda92435d",
      "signature": "904439a08211c36c894cde928eaae1b75b5dc1e12dc0d9c62d38ba2cc8ea5df4f9ca6774634ef1a95594edfff25b0493b5054c652d93f9037e2edad6fc0ee30b"
    },
    {
      "token": "abb8f4e498227ee9c58765820cd6137a76bb261e8f8d34b4b44f49d4208e37a9",
      "action": "authorize",
      "publickey": "d8fa97b2ce42fb279938b9918b3bf5a7fb68ba6a3296159f237be27cda92435d",
      "signature": "a154563161efd5fedfbc13728af0cc61995ffb3984accb102bcecf2b56e48069e66e32285aea01f0333c46a4610e6fcb86c93bad063cf39567f31b664dcdd60d"
    },
    {
      "token": "cfd2a55ef902c7fe5dc35da66c578283f4aeebbd58917e771e4e567d84d28363",
      "action": "authorize",
      "publickey": "d8fa97b2ce42fb279938b9918b3bf5a7fb68ba6a3296159f237be27cda92435d",
      "signature": "99b7a544dd9c910fa48c653a9e8ff14aa9b083227baeebd81ef35288f388c575cd65870e0cf68d5c692c6c9e4d9063e7f425601b19ad507164b8cdf1031ed90f"
    }
  ],
  "startvotes": [
    {
      "vote": {
        "token": "6ec6c28c350013873e15a37c16ffcea90dd08043ed55c44194008e167527999a",
        "proposalversion": 1,
        "type": 2,
        "mask": 3,
        "duration": 2,
        "quorumpercentage": 1,
        "passpercentage": 1,
        "options": [
          {
            "id": "yes",
            "description": "Don't approve proposal",
            "bits": 1
          },
          {
            "id": "no",
            "description": "Approve proposal",
            "bits": 2
          }
        ]
      },
      "publickey": "d8fa97b2ce42fb279938b9918b3bf5a7fb68ba6a3296159f237be27cda92435d",
      "signature": "d5c909dfa755a777d8f8678e10d955faf5c53d00b1e21c744faadbf15328ff48550b76ff8f9136ecb40b6614ebfe7ca9ee8280c4b0141fd6399a37d0705f7a0d"
    },
    {
      "vote": {
        "token": "abb8f4e498227ee9c58765820cd6137a76bb261e8f8d34b4b44f49d4208e37a9",
        "proposalversion": 1,
        "type": 2,
        "mask": 3,
        "duration": 2,
        "quorumpercentage": 1,
        "passpercentage": 1,
        "options": [
          {
            "id": "yes",
            "description": "Don't approve proposal",
            "bits": 1
          },
          {
            "id": "no",
            "description": "Approve proposal",
            "bits": 2
          }
        ]
      },
      "publickey": "d8fa97b2ce42fb279938b9918b3bf5a7fb68ba6a3296159f237be27cda92435d",
      "signature": "08f9e9669f3d40b69046b162046c1485c8d0eb32fc1a815101ba7ab25d0feb543d1dcd9825ebea8bd593d935d176ba3099987cd96564810734b0c5a01cd97501"
    },
    {
      "vote": {
        "token": "cfd2a55ef902c7fe5dc35da66c578283f4aeebbd58917e771e4e567d84d28363",
        "proposalversion": 1,
        "type": 2,
        "mask": 3,
        "duration": 2,
        "quorumpercentage": 1,
        "passpercentage": 1,
        "options": [
          {
            "id": "yes",
            "description": "Don't approve proposal",
            "bits": 1
          },
          {
            "id": "no",
            "description": "Approve proposal",
            "bits": 2
          }
        ]
      },
      "publickey": "d8fa97b2ce42fb279938b9918b3bf5a7fb68ba6a3296159f237be27cda92435d",
      "signature": "166b210404e0968e300f23961d6e5db6e253ac1b821501c3f8f6fbd7fbf07596e02c3be7114bc8387a7efc14a9a95c56b3dc0b0bea3609ecb6119ff32d60850b"
    }
  ]
}

```

Reply:

```json
{
  "startblockheight": 417842,
  "startblockhash": "00000058ff98f9f4a859ab30e81fc66cb1dabefd6a597000dd252716514bd57f",
  "endblockheight": 417860,
  "eligibletickets": [
    "000011e329fe0359ea1d2070d927c93971232c1118502dddf0b7f1014bf38d97",
    "0004b0f8b2883a2150749b2c8ba05652b02220e98895999fd96df790384888f9",
    "00107166c5fc5c322ecda3748a1896f4a2de6672aae25014123d2cedc83e8f42",
    "002272cf4788c3f726c30472f9c97d2ce66b997b5762ff4df6a05c4761272413"
  ]
}
```

Note: eligibletickets is abbreviated for readability.

### `Vote details`

Vote details returns all of the relevant proposal vote information for the
given proposal token.  This includes all of the vote parameters and voting
options.

The returned version specifies the start vote version that was used to initiate
the voting period for the given proposal. See the [`Start vote`](#start-vote)
documentation for more details on the differences between the start vote
versions.

The "vote" field is a base64 encoded JSON byte slice of the Vote and will need
to be decoded according to the returned version. See the
[`Start vote`](#start-vote) documentation for more details on the differences
between the Vote versions.

**Route:** `GET /v2/vote/{token}`

**Params:** None

**Results (VoteDetailsReply):**

| | Type | Description |
| - | - | - |
| version | number | Start vote version |
| vote | string | JSON encoded Vote |
| publickey | string | Key used for signature |
| signature | string | Start vote signature |
| startblockheight | number | Start block height of the vote |
| startblockhash | string | Start block hash of the vote |
| endblockheight | number | End block height of the vote |
| eligibletickets | []string | All ticket hashes that are eligible to vote |

On failure the call shall return `400 Bad Request` and one of the following
error codes:
- [`ErrorStatusProposalNotFound`](#ErrorStatusProposalNotFound)
- [`ErrorStatusWrongVoteStatus`](#ErrorStatusWrongVoteStatus)

**Example**

Reply:

```
{
  "version": 2,
  "vote": "{\"token\":\"9a9b823fc46c1f8cbda4c0b0956cd782c31165d22ff0ac268190e68e708477cf\",\"proposalversion\":1,\"type\":1,\"mask\":3,\"duration\":2016,\"quorumpercentage\":20,\"passpercentage\":60,\"options\":[{\"id\":\"no\",\"description\":\"Don't approve proposal\",\"bits\":1},{\"id\":\"yes\",\"description\":\"Approve proposal\",\"bits\":2}]}",
  "publickey": "8139793b84ad5efc48f395bbc53cc4be101936bc72167cd10c649e1e09bf698b",
  "signature": "994c893b6c26c17f900c06f01aa68cc8008af52fcaf0ab223aed810833dbafe6da08728d2a76ea48b45b3a75c48fb8ce89a3feb4a460ad6b6e741f248c4fff0c",
  "startblockheight": 342692,
  "startblockhash": "0000005e341105be45fb9a7fe24d5ca7879e07bfb1ed2f786ee5ebc220ac1959",
  "endblockheight": 344724,
  "eligibletickets":[
    "000011e329fe0359ea1d2070d927c93971232c1118502dddf0b7f1014bf38d97",
    "0004b0f8b2883a2150749b2c8ba05652b02220e98895999fd96df790384888f9",
    "00107166c5fc5c322ecda3748a1896f4a2de6672aae25014123d2cedc83e8f42",
    "002272cf4788c3f726c30472f9c97d2ce66b997b5762ff4df6a05c4761272413"
  ]
}
```

Note: eligibletickets is abbreviated for readability.

### `Authorize vote actions`
| Action | Value | Description |
|-|-|-|
| Authorize | authorize | Authorize a proposal vote |
| Revoke | revoke | Revoke a previous authorization | 

### `Authorize vote`
| Parameter | Value | Description |
|-|-|-|
| token | string | Proposal token of vote that is being authorized |
| action | [`AuthVoteAction`](#authorize-vote-actions) | Authorize or revoke | 
| publickey | string | Public key used for signature |
| signature | string | Signature of `token+version+action` |

### `Vote types`
| Type | Value | Description |
|-|-|-|
| <a name="VoteTypeInvalid">VoteTypeInvalid</a>| 0 | An invalid vote type. This shall be considered a bug. |
| <a name="VoteTypeStandard">VoteTypeStandard</a>| 1 | A simple approve or reject proposal vote where the winner is the voting option that has met the specified pass and quorum requirements. |
| <a name="VoteTypeRunoff">VoteTypeRunoff</a>| 2 | A runoff vote that multiple proposals compete in. All proposals are voted on like normal, but there can only be one winner in a runoff vote. The winner is the proposal that meets the quorum requirement, meets the pass requirement, and that has the most net yes votes. The winning proposal is considered approved and all other proposals are considered rejected. If no proposals meet the quorum and pass requirements then all proposals are considered rejected. Note: in a runoff vote it is possible for a proposal to meet the quorum and pass requirements but still be rejected if it does not have the most net yes votes. |

### `Vote option`

| Parameter | Type | Description |
| - | - | - |
| id | string | Single unique word that identifies this option, e.g. "yes" |
| description | string | Human readable description of this option |
| bits | number | Bits that make up this choice, e.g. 0x01 |

### `Vote`

| Parameter | Type | Description |
| - | - | - |
| token | string | Censorship token |
| proposalversion | number | Proposal version being voted on |
| type | [`VoteT`](#vote-types) | Type of proposal vote | 
| mask | number | Mask for valid vote bits |
| duration | number | Duration of the vote in blocks |
| quorumpercentage | number | Percent of eligible votes required for a quorum |
| pass percentage | number | Percent of total votes required for the proposal to considered approved | 
| options | [][`VoteOption`](#vote-option) | Vote options |

### `Start vote`

| Parameter | Type | Description | Required |
|-|-|-|-|
| publickey | string | Public key used to sign the vote | Yes |
| vote | [`Vote`](#vote) | Vote details | Yes |
| signature | string | Signature of the Vote digest | Yes |
