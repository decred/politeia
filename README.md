# Politeia
[![Build Status](https://img.shields.io/travis/decred/politeia.svg)](https://travis-ci.org/decred/politeia)
[![ISC License](https://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)

**Politeia is the Decred proposal system.**
Politeia is a system for storing off-chain data that is both versioned and
timestamped, essentially “git, a popular revision control system, plus
timestamping”. Instead of attempting to store all the data related to Decred’s
governance on-chain, we have opted to create an off-chain store of data that is
anchored into Decred’s blockchain, minimizing its on-chain footprint.

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
* politeia_verify - Reference verification tool.
* politeiawww - Web backend server.
* politeiawww_refclient - Web reference client application.
* politeiawww_dbutil - Politeiawww database tool for debugging and creating
admin users.

Note that politeiawww does not provide HTML output.  It strictly handles the
JSON REST RPC commands only.  The GUI for politeiawww can be found at:
https://github.com/decred/politeiagui

## Development

#### 1. Install [Go](https://golang.org/doc/install) and [dep](https://github.com/golang/dep), if you haven't already.
#### 2. Clone this repository.
#### 3. Setup configuration files:
* `politeiad` and `politeiawww` both have configuration files that you should
set up to make execution easier.
* You should create the configuration files under the following path:
  - **macOS** `/Users/<username>/Library/Application Support/Politeiad/politeiad.conf`
  - **Windows** `C:\Users\<username>\AppData\Local\Politeiad/politeiad.conf`
  - **Ubuntu** `~/.politeiad/politeiad.conf`

* Copy and change the  [`sample-politeiawww.conf`](https://github.com/decred/politeia/blob/master/politeiawww/sample-politeiawww.conf)
and [`sample-politeiad.conf`](https://github.com/decred/politeia/blob/master/politeiad/sample-politeiad.conf) files.
* You may use the following default configurations:

**politeiad.conf**:

    rpcuser=user
    rpcpass=pass
    testnet=true


**politeiawww.conf**:

    rpchost=127.0.0.1
    rpcuser=user
    rpcpass=pass
    rpccert="/Users/<username>/Library/Application Support/Politeiad/https.cert"
    proxy=true
    testnet=true

**note 1:** The rpccert path is referenced on macOS path. See above for
more OS paths.

**note 2:** politeiawww uses an email server to send verification codes for
things like new user registration, and those settings are also configured within
 `politeiawww.conf`. See [below](#setting-up-an-smtp-server) for more
 information.

#### 4. Build the programs:
```
cd $GOPATH/src/github.com/decred/politeia
dep ensure && go install -v ./...
```
#### 5. Start the Politeiad server by running on your terminal:

    politeiad

#### 6. Download server identity to client:

    politeia -v -testnet -rpchost 127.0.0.1 identity

Accept politeiad's identity by pressing `enter`.

Result should look something like this:

```
FQDN       : localhost
Nick       : politeiad
Key        : dfd6caacf0bbe5725efc67e703e912c37931b4edbf17122947a1e0fcd9755f6d
Identity   : 99e748e13d7ecf70ef6b5afa376d692cd7cb4dbb3d26fa83f417d29e44c6bb6c
Fingerprint: medI4T1+z3Dva1r6N21pLNfLTbs9JvqD9BfSnkTGu2w=

Save to /Users/<username>/Library/Application Support/Politeia/identity.json or ctrl-c to abort
Identity saved to: /Users/<username>/Library/Application Support/Politeia/identity.json
```

#### 7. Start the Politeiawww server by running on your terminal:

    politeiawww

**Awesome!** From this point you have your politeia server up running!

#### 8. Running the politeiawww reference client:
* With politeiad and politeiawww running type on your terminal:
```
politeiawww_refclient
```
Result should look something like this:
```
=== Start ===
Request: GET /
Version: 1
Route  : /v1
CSRF   :

Request: GET /v1/policy
Request: POST /v1/user/new
Request: GET /v1/user/verify/?email=2e645574ba5dcf42@example.com&verificationtoken=41b27466ea295a9fd9e521d2aa2e8fc7837d48441fb6af8106abc4ecd929c94d&signature=546509014b4257b47186944f3ba47ed6e7077e3862cf635b0f4b9350ab3cf6c24ff8d341f65ecabc51b8dbeb8098deaa2c26d3faf4edbd6a6aa2aec47cd92b0a
Request: POST /v1/proposals/new
[...]
refclient run successful
=== End ===
```
* The generated email is what gives you access to the PoliteiaGUI application
where your password will be the email's username. Example:
```
email: 2e645574ba5dcf42@example.com
password: 2e645574ba5dcf42
```
**Note:** Make sure you do not have an email server set up for politeiawww,
because politeiawww_refclient will not execute correctly. So before you execute
politeiawww_refclient, make sure to comment out or remove the following config
options and restart politeiawww: mailhost, mailuser, mailpass,
webserveraddress."

#### 9. Elevating user permission with politeiawww_dbutil
* This tool allows you to elevate a user in politeiawww to have admin
permissions. You will have to shut down politeiawww, and then execute in your
terminal:

`politeiawww_dbutil -testnet -setadmin <email> <true/false>`

## Integrated Projects / External APIs / Official Development URLs
* https://faucet.decred.org - instance of [testnetfaucet](https://github.com/decred/testnetfaucet)
  which is used by **politeiawww_refclient** to satisfy paywall requests in an
  automated fashion.
* https://test-proposals.decred.org/ - testing/development instance of
  [politeiagui](https://github.com/decred/politeiagui).

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

## Further guidance

#### Paywall
The paywall functionality of politeia requires a master public key for an
account to derive payment addresses.  You may either use one of the
pre-generated test keys (grep the source for tpub) or you may acquire one by
creating accounts and retrieving the public keys for those accounts:

Put the result of the following command as paywallxpub=tpub... in
politeiawww.conf.

```
dcrctl --wallet --testnet createnewaccount politeiapayments
dcrctl --wallet --testnet getmasterpubkey politeiapayments
```
#### Using Politeia with command line

- **Send proposal:**
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

- **Publishing a proposal (requires credentials):**
```
politeia -testnet -rpchost 127.0.0.1 -rpcuser user -rpcpass pass setunvettedstatus publish 6284c5f8fba5665373b8e6651ebc8747b289fed242d2f880f64a284496bb4ca8
Set proposal status:
  Status   : public
```

- **Censoring a proposal (requires credentials):**
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

#### nginx reverse proxy sample

##### testnet
```
# politeiawww
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

# politeiagui
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
#### Setting up an SMTP server
The current code should work with most SSL-based SMTP servers (but not TLS)
using username and password as authentication.
