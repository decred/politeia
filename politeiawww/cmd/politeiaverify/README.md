# politeiaverify

`politeiaverify` is a tool that allows anyone to independently verify data
submitted to Politeia. This includes:

- Censorship records - a user is provided with a censorship record whenever a
  record is submitted or updated. A censorship record provides cryptographic
  proof that a record was received by Politeia.

- Plugin receipts - when plugin data is submitted, such as a new comment, a
  receipt is returned by the server. The receipt provide cryptographic proof
  that the data was received by politeia.

- User signatures - anytime a user submits any type of data to Politeia they
  must sign the data using a key that is specific to the user. The public key
  and signature are saved along with the data, providing cryptographic proof
  that the data was submitted by the user.

- Timestamps - all data submitted to Politeia is timestamped onto the Decred
  blockchain. A timestamp provides cryptographic proof that the data existed at
  a specific block height and has not been altered since then.

## Usage

```
politeiaverify [flags] <filepaths>...`

Options:
 -k       Politiea's public server key
 -t       Record censorship token
 -s       Record censorship signature
```

## Verifying politeiagui bundles

File bundles that are available for download in politeiagui can be passed
directly into `politeiaverify`. These files contain everything needed to verify
their contents. Files accepted by this tool are listed below.

```
Record bundle     : [token]-[version].json
Record timestamps : [token]-[version]-timestamps.json
Comments bundle   : [token]-comments.json
Comment timestamps: [token]-comments-timestamps.json
Votes bundle      : [token]-votes.json
Vote timestamps   : [token]-votes-timestamps.json
```

### Example: Verifying a record bundle
```
$ politeiaverify 98ddf0b2fe580c43-v2.json

Server public key: bb5b37a6984871bf061cb4a2c9d0f3a3e102dacc810703d49b6d3641a9d08a9b
Censorship record
  Token      : 98ddf0b2fe580c43
  Merkle root: 1be0528f55ed7a6a299cecf2b625d327959f104672b1d287c9b00cae7ab0f493
  Signature  : 5c91db205f65539a14ae3061b86a27830fc16eb4a345390cfcfb0fbc21a4c931be3f72e9556409c302154dcb99b89c64556400f4d8bd5e4ce720500e2b7fd50a
Censorship record verified!

Author metadata:
  ID        : d98122ad-4012-4b62-8539-69fb0d53f417
  Public key: 869616157b35bcd7d13b8c3ce9b895f2e50dd8c7f0c42a550c6905c6aad6e17b
  Signature : b298d086be8f02e8ad490e907beea17340ba6306604467fa145bdebbd94842df5024077f0a5be6b203493a4079f34807ba03963bc72a53cd8b8b953302495b0d
Author signature verified!

Status change: public
  Public key   : bc510d90ff9d88187c41837ee11c50f40f3c262f2e1564bb2e75ea9451b102a0
  Signature    : d02ab197aa24244752dab6aa0445741c77d6f10690775a4ea18c9d07fe84569c8f54777792d9c0e1383a4399ccfa952bd9d556348194ac011970fa67f0c0ac0a
Status change signatures verified!
```

### Example: Verifying record timestamps
```
$ politeiaverify 98ddf0b2fe580c43-v2-timestamps.json

Merkle root: 80d9cdb73017571d932bd6aef5336c4a3e88ad284f987d54f929eb16254b4edf
DCR tx     : 149c04fec4c2dd3bc01694a4e8db126211ac8ed726db71e976a82525ac42490a
Record contents
  Metadata
    usermd 1
    usermd 2
  Files
    index.md
    proposalmetadata.json
Timestamps successfully verified!
The merkle root can be found in the OP_RETURN of the DCR tx.
```

## Manual verification

When verifying manually the user must provide the server public key (`-k`),
the censorship token (`-t`), the censorship record signature (`-s`), and the
file paths for all files that were part of the record.

```
$ politeiaverify \
-k e88df79a4b02699e6c051adbae05f21f2a2f24942e0f27cade165548ec3d6387 \
-t 39868e5e91c78255 \
-s b2a69823f85b62941d845c439726a2504026a0d29fd50ecabe5648b0128328c2fade0ddb354594d48a209dff24e73795ec9cb175d028155cbfa1901114f4b608 \
index.md

Server key : e88df79a4b02699e6c051adbae05f21f2a2f24942e0f27cade165548ec3d6387
Token      : 39868e5e91c78255
Merkle root: 2d00aaa0768701fd011943fbe8ae92f84ee268ca134d6b14f877c3153072bb3c
Signature  : b2a69823f85b62941d845c439726a2504026a0d29fd50ecabe5648b0128328c2fade0ddb354594d48a209dff24e73795ec9cb175d028155cbfa1901114f4b608

Record successfully verified
```
