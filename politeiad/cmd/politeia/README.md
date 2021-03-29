# politeia refclient examples

```
Available commands:
  identity         Get server identity
  new              Submit new record
                   Args: [metadata:<id>:metadataJSON]... <filepaths>...
  verify           Verify record was accepted 
                   Args: <serverkey> <token> <signature> <filepaths>...
  edit             Edit record
                   Args: [actionMetadata:<id>:metadataJSON]... 
                         <actionfile:filename>... token:<token>
  editmetadata     Edit record metdata 
                   Args: [actionMetadata:<id>:metadataJSON]... token:<token>
  setstatus        Set record status 
                   Args: <token> <status>
  record           Get a record 
                   Args: <token>
  inventory        Get the record inventory 
                   Args (optional): <state> <status> <page>
```

## Obtain politeiad identity

The politeiad identity is the contains the public key that is sued to verify
replies from politeiad. 

```
$ politeia  -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass identity

Key        : e88df79a4b02699e6c051adbae05f21f2a2f24942e0f27cade165548ec3d6387
Fingerprint: 6I33mksCaZ5sBRrbrgXyHyovJJQuDyfK3hZVSOw9Y4c=

Save to /home/user/.politeia/identity.json or ctrl-c to abort
Identity saved to: /home/user/.politeia/identity.json
```

## Submit a new record

Args: `[metadata:<id>:metadataJSON]... <filepaths>...`

At least one file must be submitted. This example uses an `index.md` file.

Metadata is submitted as JSON and must be identified by a `pluginID` string and
a `streamID` uint32. Metadata is passed in as an argument by prefixing the JSON
with `metadata:[pluginID][streamID]:`. Below is an example metadata argument
where the plugin ID is `testid` and the stream ID is `1`.

`metadata:testid1:{"foo":"bar"}`

```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass new \
'metadata:testid1:{"moo":"lala"}' 'metadata:testid12:{"foo":"bar"}' index.md

Record submitted:
  Status     : unreviewed
  Timestamp  : 2021-03-25 16:36:40 +0000 UTC
  Version    : 1
  Censorship record:
    Merkle   : 2d00aaa0768701fd011943fbe8ae92f84ee268ca134d6b14f877c3153072bb3c
    Token    : 39868e5e91c78255
    Signature: b2a69823f85b62941d845c439726a2504026a0d29fd50ecabe5648b0128328c2fade0ddb354594d48a209dff24e73795ec9cb175d028155cbfa1901114f4b608
  File (00)  :
    Name     : index.md
    MIME     : text/plain; charset=utf-8
    Digest   : 2d00aaa0768701fd011943fbe8ae92f84ee268ca134d6b14f877c3153072bb3c
  Metadata stream testid 01:
    {"moo":"lala"}
  Metadata stream testid 12:
    {"foo":"bar"}
Server public key: e88df79a4b02699e6c051adbae05f21f2a2f24942e0f27cade165548ec3d6387
```

## Verify record

Args: `<serverKey> <token> <signature> <filepaths>...`

Verify a record was recieved by the server by verifying the censorship
record signature.

```
$ politeia verify \
e88df79a4b02699e6c051adbae05f21f2a2f24942e0f27cade165548ec3d6387 \
39868e5e91c78255 \
b2a69823f85b62941d845c439726a2504026a0d29fd50ecabe5648b0128328c2fade0ddb354594d48a209dff24e73795ec9cb175d028155cbfa1901114f4b608 \
index.md

Server key : e88df79a4b02699e6c051adbae05f21f2a2f24942e0f27cade165548ec3d6387
Token      : 39868e5e91c78255
Merkle root: 2d00aaa0768701fd011943fbe8ae92f84ee268ca134d6b14f877c3153072bb3c
Signature  : b2a69823f85b62941d845c439726a2504026a0d29fd50ecabe5648b0128328c2fade0ddb354594d48a209dff24e73795ec9cb175d028155cbfa1901114f4b608

Record successfully verified
```

## Edit record

Args: `[actionMetadata:<id>:metadataJSON]...  <actionfile:filename>...
token:<token>`

Metadata can be updated using the arguments:  
`'appendmetadata:[pluginID][streamID]:[metadataJSON]'`  
`'overwritemetadata:[pluginID][streamID]:[metadataJSON]'`  

Files can be updated using the arguments:  
`add:[filepath]`  
`del:[filename]`  

The token is specified using the argument:  
`token:[token]`

Metadata provided using the `overwritemetadata` argument does not have to
already exist.

```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass edit \
'appendmetadata:testid1:{"foo":"bar"}' \
'overwritemetadata:testid12:{"12foo":"12bar"}' \
del:index.md add:updated.md token:39868e5e91c78255

Record updated:
  Status     : unreviewed
  Timestamp  : 2021-03-25 16:38:59 +0000 UTC
  Version    : 2
  Censorship record:
    Merkle   : db09a4371b32086241999b7db196c4bda04bd93194cdb90940a88741d5bbf166
    Token    : 39868e5e91c78255
    Signature: 7f26ab5d5fc4a67cfe6320fa1a1c2cbb5d6dadbfcd74d255d0c048c32e9da413cfb8cdcc9440c53300ce0907c7d274435d4e98c36c189dfcc81dbecc44e79003
  File (00)  :
    Name     : updated.md
    MIME     : text/plain; charset=utf-8
    Digest   : db09a4371b32086241999b7db196c4bda04bd93194cdb90940a88741d5bbf166
  Metadata stream testid 12:
    {"12foo":"12bar"}
  Metadata stream testid 01:
    {"moo":"lala"}{"foo":"bar"}
Server public key: e88df79a4b02699e6c051adbae05f21f2a2f24942e0f27cade165548ec3d6387
```

## Edit record metadata

Args: `[actionMetadata:<id>:metadataJSON]... token:<token>`

Metadata can be updated when updating the record files or the client can
perform a metadata only update using this command. Updating only the metadata
will not change the censorship record signature.

Metadata can be updated using the arguments:  
`'appendmetadata:[pluginID][streamID]:[metadataJSON]'`  
`'overwritemetadata:[pluginID][streamID]:[metadataJSON]'`  

The token is specified using the argument:  
`token:[token]`

Metadata provided using the `overwritemetadata` argument does not have to
already exist.

```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass editmetadata \
'appendmetadata:testid1:{"foo":"bar"}' \
'overwritemetadata:testid12:{"123foo":"123bar"}' \
token:39868e5e91c78255

Record metadata updated:
  Status     : unreviewed
  Timestamp  : 2021-03-25 16:39:35 +0000 UTC
  Version    : 2
  Censorship record:
    Merkle   : db09a4371b32086241999b7db196c4bda04bd93194cdb90940a88741d5bbf166
    Token    : 39868e5e91c78255
    Signature: 7f26ab5d5fc4a67cfe6320fa1a1c2cbb5d6dadbfcd74d255d0c048c32e9da413cfb8cdcc9440c53300ce0907c7d274435d4e98c36c189dfcc81dbecc44e79003
  File (00)  :
    Name     : updated.md
    MIME     : text/plain; charset=utf-8
    Digest   : db09a4371b32086241999b7db196c4bda04bd93194cdb90940a88741d5bbf166
  Metadata stream testid 12:
    {"123foo":"123bar"}
  Metadata stream testid 01:
    {"moo":"lala"}{"foo":"bar"}{"foo":"bar"}
Server public key: e88df79a4b02699e6c051adbae05f21f2a2f24942e0f27cade165548ec3d6387
```

## Set record status

Args: `<token> <status>`

You can update the status of a record using one of the following statuses:
- `public`   - make the record a public
- `archived` - lock the record from further edits
- `censored` - lock the record from further edits and delete all files

Note, token is not prefixed with `token:` in this command.

```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass setstatus 39868e5e91c78255 public

Record status updated:
  Status     : public
  Timestamp  : 2021-03-25 16:40:40 +0000 UTC
  Version    : 1
  Censorship record:
    Merkle   : db09a4371b32086241999b7db196c4bda04bd93194cdb90940a88741d5bbf166
    Token    : 39868e5e91c78255
    Signature: 7f26ab5d5fc4a67cfe6320fa1a1c2cbb5d6dadbfcd74d255d0c048c32e9da413cfb8cdcc9440c53300ce0907c7d274435d4e98c36c189dfcc81dbecc44e79003
  File (00)  :
    Name     : updated.md
    MIME     : text/plain; charset=utf-8
    Digest   : db09a4371b32086241999b7db196c4bda04bd93194cdb90940a88741d5bbf166
  Metadata stream testid 01:
    {"moo":"lala"}{"foo":"bar"}{"foo":"bar"}
  Metadata stream testid 12:
    {"123foo":"123bar"}
Server public key: e88df79a4b02699e6c051adbae05f21f2a2f24942e0f27cade165548ec3d6387
```

## Get record

Retrieve a record.

```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass record 39868e5e91c78255

Record:
  Status     : public
  Timestamp  : 2021-03-25 16:40:40 +0000 UTC
  Version    : 1
  Censorship record:
    Merkle   : db09a4371b32086241999b7db196c4bda04bd93194cdb90940a88741d5bbf166
    Token    : 39868e5e91c78255
    Signature: 7f26ab5d5fc4a67cfe6320fa1a1c2cbb5d6dadbfcd74d255d0c048c32e9da413cfb8cdcc9440c53300ce0907c7d274435d4e98c36c189dfcc81dbecc44e79003
  File (00)  :
    Name     : updated.md
    MIME     : text/plain; charset=utf-8
    Digest   : db09a4371b32086241999b7db196c4bda04bd93194cdb90940a88741d5bbf166
  Metadata stream testid 12:
    {"123foo":"123bar"}
  Metadata stream testid 01:
    {"moo":"lala"}{"foo":"bar"}{"foo":"bar"}
Server public key: e88df79a4b02699e6c051adbae05f21f2a2f24942e0f27cade165548ec3d6387
```

## Inventory

Retrieve the censorship record tokens of the records in the inventory,
categorized by their record state and record status.

The user can request a page of tokens from a specific record state and record
status by providing the <state> <status> <pageNumber> arguments.

States: `unvetted`, `vetted`  
Statuses: `unreviewed`, `public`, `censored`, `abandoned`  

```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass inventory unvetted unreviewed 1 

Unvetted
{
  "unreviewed": [
    "d0545038224c5054",
    "ea260a4ab9170d70"
  ]
}
```

If not arguments are provided then a page of tokens for every state and status
will be returned.

```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass inventory

Unvetted
{
  "censored": [
    "de127f2cb24c702b",
  ],
  "unreviewed": [
    "d0545038224c5054",
    "ea260a4ab9170d70"
  ]
}
Vetted
{
  "archived": [
    "77396eccc387b07e"
  ],
  "censored": [
    "0439c5355ef94e36"
  ],
  "public": [
    "39868e5e91c78255",
    "2f5d6bbb15b63e76",
    "f1f7337397a79b51"
  ]
}
```
