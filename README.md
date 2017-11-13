# politeia
[![Build Status](http://img.shields.io/travis/decred/politeia.svg)](https://travis-ci.org/decred/politeia)
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
* politeia_verify - Reference verification tool.
* politeiawww - Web backend server.
* politeiawww_refclient - Web reference client application.
* politeiawww_dbutil - Politeiawww database tool for debugging and creating admin users.

Note that politeiawww does not provide HTML output.  It strictly handles the
JSON REST RPC commands only.  The GUI for politeiawww can be found at:
https://github.com/decred/politeiagui

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
politeia -v -testnet -rpchost 127.0.0.1 identity
```
Accept default path by pressing `enter`.

Result should look something like this:
```
FQDN       : localhost
Nick       : politeiad
Key        : dfd6caacf0bbe5725efc67e703e912c37931b4edbf17122947a1e0fcd9755f6d
Identity   : 99e748e13d7ecf70ef6b5afa376d692cd7cb4dbb3d26fa83f417d29e44c6bb6c
Fingerprint: medI4T1+z3Dva1r6N21pLNfLTbs9JvqD9BfSnkTGu2w=

Save to /Users/marco/Library/Application Support/Politeia/identity.json or ctrl-c to abort
Identity saved to: /Users/marco/Library/Application Support/Politeia/identity.json
```

Send proposal:
```
politeia -v -testnet -rpchost 127.0.0.1 new "My awesome proposal" proposal.txt spec.txt
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
politeia -testnet -rpchost 127.0.0.1 -rpcuser user -rpcpass pass setunvettedstatus publish 6284c5f8fba5665373b8e6651ebc8747b289fed242d2f880f64a284496bb4ca8
Set proposal status:
  Status   : public
```

Censoring a proposal (requires credentials):
```
politeia -testnet -rpchost 127.0.0.1 -rpcuser user -rpcpass pass setunvettedstatus censor 527cb21b78a56d597f5ab4c199195343ecfcd56cf0d76910b2a63c97635a6532
Set proposal status:
  Status   : censored
```

To independently verify that Politeia has received your proposal, you can use
the `politeia_verify` tool and provide politeiad's public key, the proposal's
censorship token and signature, and the proposal files:

```
politeia_verify -v -k dfd6caacf0bbe5725efc67e703e912c37931b4edbf17122947a1e0fcd9755f6d -t 6284c5f8fba5665373b8e6651ebc8747b289fed242d2f880f64a284496bb4ca8 -s 82d69b4ec83d2a732fe92028dbf78853d0814aeb4fcf0ff597c110c8843720951f7b9fae4305b0f1d9346c39bc960a364590236f9e0871f6f79860fc57d4c70 proposal.md
Proposal successfully verified.
```

If the proposal fails to verify, it will return an error:

```
politeia_verify -v -k xfd6caacf0bbe5725efc67e703e912c37931b4edbf17122947a1e0fcd9755f6d -t 6284c5f8fba5665373b8e6651ebc8747b289fed242d2f880f64a284496bb4ca8 -s 82d69b4ec83d2a732fe92028dbf78853d0814aeb4fcf0ff597c110c8843720951f7b9fae4305b0f1d9346c39bc960a364590236f9e0871f6f79860fc57d4c70 proposal.md
Proposal failed verification. Please ensure the public key and merkle are correct.
  Merkle: 0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8

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

## nginx reverse proxy sample

### testnet
```
location /api/ {
	# disable caching
	expires off;

	proxy_set_header Host $host;
	proxy_set_header X-Forwarded-For $remote_addr;
	proxy_set_header Upgrade $http_upgrade;
	proxy_set_header Connection "upgrade";
	proxy_bypass_cache $http_upgrade;

	proxy_http_version 1.1;
	proxy_ssl_trusted_certificated /path/to/politeiawww.crt;
	proxy_ssl_verify on;
	proxy_pass https://test-politeia.domain.com:4443/;
}

# aesthetics.
location /user/verify {
	# redirect not found
	error_page 404 =200 /;
	proxy_intercept_errors on;

	# disable caching
	expires off;

	proxy_set_header Host $host;
	proxy_set_header X-Forwarded-For $remote_addr;
	proxy_set_header Upgrade $http_upgrade;
	proxy_set_header Connection "upgrade";
	proxy_bypass_cache $http_upgrade;

	proxy_http_version 1.1;
        proxy_ssl_trusted_certificated /path/to/politeiawww.crt;
        proxy_ssl_verify on;
        proxy_pass https://test-politeia.domain.com:4443/v1/user/verify;
}

location / {
	# redirect not found
	error_page 404 =200 /;
	proxy_intercept_errors on;

	# disable caching
	expires off;

	proxy_set_header Host $host;
	proxy_set_header X-Forwarded-For $remote_addr;
	proxy_set_header Upgrade $http_upgrade;
	proxy_set_header Connection "upgrade";
	proxy_http_version 1.1;

	# backend
	proxy_pass http://127.0.0.1:8000;
}
```
