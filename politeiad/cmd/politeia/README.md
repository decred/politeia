# politeia refclient examples

Obtain politeiad identity:
```
$ politeia  -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass identity
Key        : 8f627e9da14322626d7e81d789f7fcafd25f62235a95377f39cbc7293c4944ad
Fingerprint: j2J+naFDImJtfoHXiff8r9JfYiNalTd/OcvHKTxJRK0=

Save to /home/marco/.politeia/identity.json or ctrl-c to abort
Identity saved to: /home/marco/.politeia/identity.json
```

Add a new record:
```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass new 'metadata12:{"moo":"lala"}' 'metadata2:{"foo":"bar"}' a
00: 22e88c7d6da9b73fbb515ed6a8f6d133c680527a799e3069ca7ce346d90649b2 a text/plain; charset=utf-8
Record submitted
  Censorship record:
    Merkle   : 22e88c7d6da9b73fbb515ed6a8f6d133c680527a799e3069ca7ce346d90649b2
    Token    : 72fe14a914783eafb78adcbcd405e723c3f55ff475043b0d89b2cf71ffc6a2d4
    Signature: 28c75019fb15af4e81ee1607deff58a8a82896d6bb1af4e813c5c996069ad7872505e4f25e067e8f310af82981aca1b02050ee23029f6d1e87b8ea8f0b3bcd08
```

Get unvetted record:
```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass getunvetted 43c2d4a2c846c188ab0b49012ed17e5f2c16bd6e276cfbb42e30352dffb1743f
Unvetted record:
  Status     : censored
  Timestamp  : 2017-12-14 17:08:33 +0000 UTC
  Censorship record:
    Merkle   : 22e88c7d6da9b73fbb515ed6a8f6d133c680527a799e3069ca7ce346d90649b2
    Token    : 43c2d4a2c846c188ab0b49012ed17e5f2c16bd6e276cfbb42e30352dffb1743f
    Signature: 5c28d2a93ff9cfe35e8a6b465ae06fa596b08bfe7b980ff9dbe68877e7d860010ec3c4fd8c8b739dc4ceeda3a2381899c7741896323856f0f267abf9a40b8003
  Metadata   : [{2 {"foo":"bar"}} {12 "zap"}]
  File (00)  :
    Name     : a
    MIME     : text/plain; charset=utf-8
    Digest   : 22e88c7d6da9b73fbb515ed6a8f6d133c680527a799e3069ca7ce346d90649b2
```

Update an unvetted record:
```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass updateunvetted 'appendmetadata12:{"foo":"bar"}' 'overwritemetadata2:{"12foo":"12bar"}' del:a add:b token:72fe14a914783eafb78adcbcd405e723c3f55ff475043b0d89b2cf71ffc6a2d4
Update record: 72fe14a914783eafb78adcbcd405e723c3f55ff475043b0d89b2cf71ffc6a2d4
  Files add         : 00: 12a31b5e662dfa0a572e9fc523eb703f9708de5e2d53aba74f8ebcebbdb706f7 b text/plain; charset=utf-8
  Files delete      : a
  Metadata overwrite: 2
  Metadata append   : 12
```

Censor a record (and zap metadata stream 12):
```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass setunvettedstatus censor 43c2d4a2c846c188ab0b49012ed17e5f2c16bd6e276cfbb42e30352dffb1743f 'overwritemetadata12:"zap"'
Set record status:
  Status   : censored
```

Publish a record:
```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass setunvettedstatus publish 72fe14a914783eafb78adcbcd405e723c3f55ff475043b0d89b2cf71ffc6a2d4               
Set record status:
  Status   : public
```

Get vetted record:
```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass getvetted 72fe14a914783eafb78adcbcd405e723c3f55ff475043b0d89b2cf71ffc6a2d4
Vetted record:
  Status     : public
  Timestamp  : 2017-12-14 17:06:21 +0000 UTC
  Censorship record:
    Merkle   : 12a31b5e662dfa0a572e9fc523eb703f9708de5e2d53aba74f8ebcebbdb706f7
    Token    : 72fe14a914783eafb78adcbcd405e723c3f55ff475043b0d89b2cf71ffc6a2d4
    Signature: 25483966ec6e8df90398c197e3bdb74fe5356df0c96927d771b06e83a7fb29e069751118f4496e42d02a63feb74d67b777c69bb8f356aeafca873325aaf8010f
  Metadata   : [{2 {"12foo":"12bar"}} {12 {"moo":"lala"}{"foo":"bar"}}]
  File (00)  :
    Name     : b
    MIME     : text/plain; charset=utf-8
    Digest   : 12a31b5e662dfa0a572e9fc523eb703f9708de5e2d53aba74f8ebcebbdb706f7
```

Update a vetted record:
```
$ politeia -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass updatevetted 'appendmetadata12:{"foo":"bar"}' 'overwritemetadata2:{"12foo":"12bar"}' del:a add:b token:72fe14a914783eafb78adcbcd405e723c3f55ff475043b0d89b2cf71ffc6a2d4
Update record: 72fe14a914783eafb78adcbcd405e723c3f55ff475043b0d89b2cf71ffc6a2d4
  Files add         : 00: 12a31b5e662dfa0a572e9fc523eb703f9708de5e2d53aba74f8ebcebbdb706f7 b text/plain; charset=utf-8
  Files delete      : a
  Metadata overwrite: 2
  Metadata append   : 12
```

Inventory all records:
```
politeia  -v -testnet -rpchost 127.0.0.1 -rpcuser=user -rpcpass=pass inventory 1 1
Vetted record:
  Status     : public
  Timestamp  : 2017-12-14 17:06:21 +0000 UTC
  Censorship record:
    Merkle   : 12a31b5e662dfa0a572e9fc523eb703f9708de5e2d53aba74f8ebcebbdb706f7
    Token    : 72fe14a914783eafb78adcbcd405e723c3f55ff475043b0d89b2cf71ffc6a2d4
    Signature: 25483966ec6e8df90398c197e3bdb74fe5356df0c96927d771b06e83a7fb29e069751118f4496e42d02a63feb74d67b777c69bb8f356aeafca873325aaf8010f
  Metadata   : [{2 {"12foo":"12bar"}} {12 {"moo":"lala"}{"foo":"bar"}}]
Unvetted record:
  Status     : censored
  Timestamp  : 2017-12-14 17:08:33 +0000 UTC
  Censorship record:
    Merkle   : 22e88c7d6da9b73fbb515ed6a8f6d133c680527a799e3069ca7ce346d90649b2
    Token    : 43c2d4a2c846c188ab0b49012ed17e5f2c16bd6e276cfbb42e30352dffb1743f
    Signature: 5c28d2a93ff9cfe35e8a6b465ae06fa596b08bfe7b980ff9dbe68877e7d860010ec3c4fd8c8b739dc4ceeda3a2381899c7741896323856f0f267abf9a40b8003
  Metadata   : [{2 {"foo":"bar"}} {12 {"moo":"lala"}}]
```
