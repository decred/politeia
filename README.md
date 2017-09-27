# politeia
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)

Politeia is the Decred proposal system.

The politeia stack is as follows:

```
~~~~~~~~ Internet ~~~~~~~~~
            |
+-------------------------+
|      politeia www       |
+-------------------------+
            |
+-------------------------+
|        politeiad        |
+-------------------------+
|       git backend       |
+-------------------------+
            |
~~~~~~~~ Internet ~~~~~~~~~
            |
+-------------------------+
|        dcrtimed         |
+-------------------------+
```

## Components
* politeia - Reference client application.
* politeiad - Reference server daemon.
* politeiaddumpdb - Politeiad database dumper for debugging purposes.
* politeiawww - Web backend server.
* politeiawww_refclient - Web reference client application.

## Dependencies
* git - the git command line tool must be installed on the machine that runs
  politeiad and be in the PATH.  The version that was used to validate the
  daemon is 2.11.0.

## Library and interfaces
* politeiad/api/v1 - JSON REST API for politeia clients.
* politeiad/cmd/politeia - Client reference implementation
* politeiawww/api/v1 - JSON API for WWW.
* politeiawww/cmd/politeiawww_refclient - Reference implementation for WWW API.
* util - common used miscellaneous utility functions.

## Example

Compile and launch the politeia daemon:
```
dep ensure && go install -v ./politeiad/... && LOGFLAGS=shortfile politeiad --testnet --rpcuser=user --rpcpass=pass
```

Download server identity to client:
```
politeia -v -testnet identity
```
Accept default path by pressing `enter`.

Result should look something like this:
```
FQDN       : politeia.testnet.decred.org
Nick       : politeiad
Key        : dfd6caacf0bbe5725efc67e703e912c37931b4edbf17122947a1e0fcd9755f6d
Identity   : 99e748e13d7ecf70ef6b5afa376d692cd7cb4dbb3d26fa83f417d29e44c6bb6c
Fingerprint: medI4T1+z3Dva1r6N21pLNfLTbs9JvqD9BfSnkTGu2w=

Save to /Users/marco/Library/Application Support/Politeia/identity.json or ctrl-c to abort
Identity saved to: /Users/marco/Library/Application Support/Politeia/identity.json
```

Send proposal:
```
politeia -v -testnet new "My awesome proposal" proposal.txt spec.txt
```

Result will look something like:
```
00: 331ea9090db0c9f6f597bd9840fd5b171830f6e0b3ba1cb24dfa91f0c95aedc1 proposal.txt text/plain; charset=utf-8
01: be0997732fa648fd083baa85e782d9e4768602dbe8a0a431ba17a01000ba93db spec.txt text/plain; charset=utf-8
Submitted proposal name: My awesome proposal
Censorship record:
  Merkle   : 8e125a9c791634f6f68672c7bc3b71dc50f986a0525e3e7361ad180cadbf6347
  Token    : 6284c5f8fba5665373b8e6651ebc8747b289fed242d2f880f64a284496bb4ca8
  Signature: 82d69b4ec83d2a732fe92028dbf78853d0814aeb4fcf0ff597c110c8843720951f7b9fae4305b0f1d9346c39bc960a364590236f9e0871f6f79860fc57d4c70a
```

Publishing a proposal (requires credentials):
```
politeia --rpcuser user --rpcpass pass --testnet setunvettedstatus publish 6284c5f8fba5665373b8e6651ebc8747b289fed242d2f880f64a284496bb4ca8
Set proposal status:
  Status   : public
```

Censoring a proposal (requires credentials):
```
politeia --rpcuser user --rpcpass pass --testnet setunvettedstatus censor 527cb21b78a56d597f5ab4c199195343ecfcd56cf0d76910b2a63c97635a6532
Set proposal status:
  Status   : censored
```

**Note:** All politeia commands can dump the JSON output of every RPC command
by adding the -json command line flag.

Compile and launch the web server:
```
dep ensure && go install -v ./politeiawww/... && LOGFLAGS=shortfile
politeiawww --testnet --fetchidentity
politeiawww --testnet --rpcuser=user --rpcpass=pass
```
To check if the web server is running correctly:
```
politeiawww_refclient
```
