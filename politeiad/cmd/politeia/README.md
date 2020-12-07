# politeia refclient examples

Available commands:  
`identity`
`verify`
`new`
`updateunvetted`
`updateunvettedmd`
`setunvettedstatus`
`getunvetted`
`updatevetted`
`updatevettedmd`
`getvetted`
`plugin`
`plugininventory`
`inventory`

## Obtain politeiad identity

The retrieved identity is used to verify replies from politeiad. 

```
$ politeia  -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass identity

Key        : 8f627e9da14322626d7e81d789f7fcafd25f62235a95377f39cbc7293c4944ad
Fingerprint: j2J+naFDImJtfoHXiff8r9JfYiNalTd/OcvHKTxJRK0=

Save to /home/user/.politeia/identity.json or ctrl-c to abort
Identity saved to: /home/user/.politeia/identity.json
```

## Add a new record

At least one file must be submitted. This example uses an `index.md` file.

Arguments are matched against the regex `^metadata[\d]{1,2}:` to determine if
the string is record metadata. Arguments that are not classified as metadata
are assumed to be file paths.

```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass new \
  'metadata12:{"moo":"lala"}' 'metadata2:{"foo":"bar"}' index.md

00: 4bde9f923b61e26147c79500e6d6dfa27291559a74cd878c29a7f96984dd48bb index.md text/plain; charset=utf-8
Record submitted
  Censorship record:
    Merkle   : 4bde9f923b61e26147c79500e6d6dfa27291559a74cd878c29a7f96984dd48bb
    Token    : 9dfe084fccb7f27c0000
    Signature: e69a38b6e6c21021db2fe37c6b38886ef987c7347bb881e2358feb766974577a742e535d34cd4d7a140b2555b3771a194fea4be942cbd99247c143d07419bc06
$
```

## Verify a record

Verifies the censorship signature of a record to make sure it was received by
the server. It receives as input the server's public key, the record token, 
the record merkle root and the signature.

```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass verify \
  df0f5cff8d9a3c6d55429c7e9e66b13ec175768b24f20db1b91188f00f7ea4b7 \
  c800ff5195ddb2360000 \
  36a2e53b25183dcfd192224fdff1074472ad7fdf5989abf9dfb8e7972caceae1 \
  f9495f8100fc3d2d2bcd3d57705adc1f859d29f5a0ed1d999593a57de5af8c047615efb65e08e93935d071b94ee3883f15661defbfa83b503e6e84be4c18aa0b

  Record successfully verified
```

## Get unvetted record

```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass getunvetted 9dfe084fccb7f27c0000

Unvetted record:
  Status     : not reviewed
  Timestamp  : 2020-10-01 14:36:11 +0000 UTC
  Censorship record:
    Merkle   : 4bde9f923b61e26147c79500e6d6dfa27291559a74cd878c29a7f96984dd48bb
    Token    : 9dfe084fccb7f27c0000
    Signature: e69a38b6e6c21021db2fe37c6b38886ef987c7347bb881e2358feb766974577a742e535d34cd4d7a140b2555b3771a194fea4be942cbd99247c143d07419bc06
  Metadata   : [{2 {"foo":"bar"}} {12 {"moo":"lala"}}]
  Version    : 1
  File (00)  :
    Name     : index.md
    MIME     : text/plain; charset=utf-8
    Digest   : 4bde9f923b61e26147c79500e6d6dfa27291559a74cd878c29a7f96984dd48bb
```

## Update an unvetted record

Metadata can be updated using the arguments:  
`'appendmetadata[ID]:[metadataJSON]'`  
`'overwritemetadata[ID]:[metadataJSON]'`  

Files can be updated using the arguments:  
`add:[filepath]`  
`del:[filename]`  

The token is specified using the argument:  
`token:[token]`

Metadata provided using the `overwritemetadata` argument does not have to
already exist.

```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass updateunvetted \
  'appendmetadata12:{"foo":"bar"}' 'overwritemetadata2:{"12foo":"12bar"}' \
  del:index.md add:updated.md token:9dfe084fccb7f27c0000

Update record: 9dfe084fccb7f27c0000
  Files add         : 00: 22036b8b67a7c54f2bae29e1f9a11551cf62a33a038788b8f2e8f8d6e7f60425 updated.md text/plain; charset=utf-8
  Files delete      : index.md
  Metadata overwrite: 2
  Metadata append   : 12
```

## Update unvetted metadata only

Metadata can be updated using the arguments:  
`'appendmetadata[ID]:[metadataJSON]'`  
`'overwritemetadata[ID]:[metadataJSON]'`  

The token is specified using the argument:  
`token:[token]`

Metadata provided using the `overwritemetadata` argument does not have to
already exist.

```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass updateunvettedmd \
  'appendmetadata12:{"foo":"bar"}' 'overwritemetadata2:{"12foo":"12bar"}' \
  token:0e4a82a370228b710000

Update record: 0e4a82a370228b710000
  Metadata overwrite: 2
  Metadata append   : 12
```

## Set unvetted status

You can update the status of an unvetted record using one of the following
statuses:
- `censored` - keep the record unvetted and mark as censored.
- `public`   - make the record a public, vetted record.
- `archived` - archive the record.

Note `token:` is not prefixed to the token in this command. Status change
validation is done in the backend.

```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass setunvettedstatus public 0e4a82a370228b710000

Set record status:
  Status   : public
```

## Get vetted record

```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass getvetted 9dfe084fccb7f27c0000

Vetted record:
  Status     : public
  Timestamp  : 2020-10-01 14:38:43 +0000 UTC
  Censorship record:
    Merkle   : 22036b8b67a7c54f2bae29e1f9a11551cf62a33a038788b8f2e8f8d6e7f60425
    Token    : 9dfe084fccb7f27c0000
    Signature: 531e5103e9f8905d52d7bf3c6fdb40070cca4f88e69f3b6c647baf8bd84148471e378b5c137014a1f3f46a2cb9a40cdc302dea4bf828fb6dd09a858fa2748c0e
  Metadata   : [{2 {"12foo":"12bar"}} {12 {"moo":"lala"}{"foo":"bar"}}]
  Version    : 1
  File (00)  :
    Name     : updated.md
    MIME     : text/plain; charset=utf-8
    Digest   : 22036b8b67a7c54f2bae29e1f9a11551cf62a33a038788b8f2e8f8d6e7f60425
```

## Update a vetted record

Metadata can be updated using the arguments:  
`'appendmetadata[ID]:[metadataJSON]'`  
`'overwritemetadata[ID]:[metadataJSON]'`  

Files can be updated using the arguments:  
`add:[filepath]`  
`del:[filename]`  

The token is specified using the argument:  
`token:[token]`

Metadata provided using the `overwritemetadata` argument does not have to
already exist.

```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass updatevetted \
  'appendmetadata12:{"foo":"bar"}' 'overwritemetadata2:{"12foo":"12bar"}' \
  del:updated add:newfile.md token:9dfe084fccb7f27c0000  

Update record: 9dfe084fccb7f27c0000
  Files add         : 00: 22036b8b67a7c54f2bae29e1f9a11551cf62a33a038788b8f2e8f8d6e7f60425 newfile.md text/plain; charset=utf-8
  Files delete      : updated
  Metadata overwrite: 2
  Metadata append   : 12
```

## Update vetted metadata only

Metadata can be updated using the arguments:  
`'appendmetadata[ID]:[metadataJSON]'`  
`'overwritemetadata[ID]:[metadataJSON]'`  

The token is specified using the argument:  
`token:[token]`

Metadata provided using the `overwritemetadata` argument does not have to
already exist.

```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass updatevettedmd \
  'appendmetadata12:{"foo":"bar"}' 'overwritemetadata2:{"12foo":"12bar"}' \
  token:0e4a82a370228b710000

Update record: 0e4a82a370228b710000
  Metadata overwrite: 2
  Metadata append   : 12
```

## Set vetted status

You can update the status of a vetted record using one of the following
statuses:
- `censored` - keep the record unvetted and mark as censored.
- `archived` - archive the record.

Note `token:` is not prefixed to the token in this command. Status change
validation is done in the backend.

```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass setvettedstatus censored 0e4a82a370228b710000 'overwritemetadata12:"zap"'
Set record status:
  Status: censored
```

## Inventory

The `inventory` command retrieves the censorship record tokens from all records,
categorized by their record status.

```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass inventory

Inventory:
  Unvetted
    not reviewed   : 344044686e9ba76f0000, 43df32e2405065250000
    censored       : 9f104b878a83242d0000
  Vetted
    public         : e2228e7a7e7c80030000, a6c064874351f4120000
    archived       : 6b099750984e05490000
```
