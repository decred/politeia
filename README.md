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

### Core components

* politeiad - Reference server daemon.
* politeiawww - Web backend server; depends on politeiad.

### Tools and reference clients

* [politeia](https://github.com/decred/politeia/tree/master/politeiad/cmd/politeia) - Reference client application for politeiad.
* [politeia_verify](https://github.com/decred/politeia/tree/master/politeiad/cmd/politeia_verify) - Reference verification tool.
* [politeiawwwcli](https://github.com/decred/politeia/tree/master/politeiawww/cmd/politeiawwwcli) - Command-line tool for interacting with politeiawww.
* [politeiawww_refclient](https://github.com/decred/politeia/tree/master/politeiawww/cmd/politeiawww_refclient) - Reference client application for politeiawww.
* [politeiawww_dbutil](https://github.com/decred/politeia/tree/master/politeiawww/cmd/politeiawww_dbutil) - Tool for debugging and creating admin users within the politeiawww database.
* [politeiawww_dataload](https://github.com/decred/politeia/tree/master/politeiawww/cmd/politeiawww_dataload) - Tool using politeiawwwcli to load a basic dataset into politeiawww.

**Note:** politeiawww does not provide HTML output.  It strictly handles the
JSON REST RPC commands only.  The GUI for politeiawww can be found at:
https://github.com/decred/politeiagui

## Development

#### 1. Install [Go](https://golang.org/doc/install) version 1.11 or higher, and [Git](https://git-scm.com/downloads).

Make sure each of these are in the PATH.

#### 2. Clone this repository.

#### 3. Setup configuration files:

politeiad and politeiawww both have configuration files that you should
set up to make execution easier. You should create the configuration files
under the following paths:

* **macOS**

   ```
   /Users/<username>/Library/Application Support/Politeiad/politeiad.conf
   /Users/<username>/Library/Application Support/Politeiawww/politeiawww.conf
   ```

* **Windows**

   ```
   C:\Users\<username>\AppData\Local\Politeiad/politeiad.conf
   C:\Users\<username>\AppData\Local\Politeiawww/politeiawww.conf
   ```

* **Ubuntu**

   ```
   ~/.politeiad/politeiad.conf
   ~/.politeiawww/politeiawww.conf
   ```

Copy and change the [`sample-politeiawww.conf`](https://github.com/decred/politeia/blob/master/politeiawww/sample-politeiawww.conf)
and [`sample-politeiad.conf`](https://github.com/decred/politeia/blob/master/politeiad/sample-politeiad.conf) files.

You can also use the following default configurations:

**politeiad.conf**:

    rpcuser=user
    rpcpass=pass
    testnet=true
    enablecache=true
    cachehost=localhost:26257
    cacherootcert="~/.cockroachdb/certs/clients/records_politeiad/ca.crt"
    cachecert="~/.cockroachdb/certs/clients/records_politeiad/client.records_politeiad.crt"
    cachekey="~/.cockroachdb/certs/clients/records_politeiad/client.records_politeiad.key"


**politeiawww.conf**:

    mode=piwww
    rpchost=127.0.0.1
    rpcuser=user
    rpcpass=pass
    rpccert="~/.politeiad/https.cert"
    testnet=true
    paywallxpub=tpubVobLtToNtTq6TZNw4raWQok35PRPZou53vegZqNubtBTJMMFmuMpWybFCfweJ52N8uZJPZZdHE5SRnBBuuRPfC5jdNstfKjiAs8JtbYG9jx
    paywallamount=10000000
    cachehost=localhost:26257
    cacherootcert="~/.cockroachdb/certs/clients/records_politeiawww/ca.crt"
    cachecert="~/.cockroachdb/certs/clients/records_politeiawww/client.records_politeiawww.crt"
    cachekey="~/.cockroachdb/certs/clients/records_politeiawww/client.records_politeiawww.key"
    cmshost=localhost:26258
    cmsrootcert="~/.cockroachdb/certs/clients/invoices_cmsdb/ca.crt"
    cmscert="~/.cockroachdb/certs/clients/invoices_cmsdb/client.invoices_cmsdb.crt"
    cmskey="~/.cockroachdb/certs/clients/invoices_cmsdb/client.invoices_cmsdb.key"

**Things to note:**

* The `rpccert` path is referencing a macOS path. See above for
more OS paths.

* politeiawww uses an email server to send verification codes for
things like new user registration, and those settings are also configured within
 `politeiawww.conf`. The current code should work with most SSL-based SMTP servers
(but not TLS) using username and password as authentication.

#### 4. Setup politeiad cache:

politeiad stores proposal data in git repositories that are regularly backed up
to github and cryptographically timestamped onto the Decred blockchain.  The
politeiad git repositories serve as the source of truth for proposal data. A
CockroachDB database is used as a cache for proposal data in order to increase
query performance.

**The cache is not required if you're running just politeiad.  politeiad has
the cache disable by default. If you're running the full politeia stack,
politeiad and politeiawww, running the cache is required.**

politeiad has read and write access to the cache.  politeiawww has only read
access to the cache.  The flow of data is as follows:

1. politeiawww receives a command from a user
2. politeiawww creates a politeiad request for the command and sends it
3. politeiad writes new data to the git repository then updates the cache
4. politeiad returns the status of the update to politeiawww
5. politeiawww reads the updated data from the cache
6. politeiawww returns a response to the user

We use CockroachDB for the cache in the instructions below.  CockroachDB is
built to be compatible with Postgres so you can use Postgres for the cache if
you so choose.  Using Postgres for the cache has not been thoroughly tested and
bugs may exist.

Install CockroachDB using the instructions found in the [CockroachDB
Documentation](https://www.cockroachlabs.com/docs/stable/install-cockroachdb-mac.html).

Run the following commands to create the CockroachDB certificates required for
running CockroachDB with Politeia.  It's ok if the directory `~/.cockroachdb`
does not exist yet.  The script will create it.  **The directory that you pass
into the script must be the same cockroachdb directory that you use in the
politeiad and politeiawww config files when specifying `cacherootcert` and
`cachecertdir`.**

    cd $GOPATH/src/github.com/decred/politeia
    ./cachecerts.sh ~/.cockroachdb

The script will create the following certificates and directories:

    .cockroachdb
    ├── ca.key
    ├── certs
    │   ├── ca.crt
    │   ├── clients
    │   │   ├── records_politeiad
    │   │   │   ├── ca.crt
    │   │   │   ├── client.records_politeiad.crt
    │   │   │   └── client.records_politeiad.key
    │   │   ├── records_politeiawww
    │   │   │   ├── ca.crt
    │   │   │   ├── client.records_politeiawww.crt
    │   │   │   └── client.records_politeiawww.key
    │   │   └── root
    │   │       ├── ca.crt
    │   │       ├── client.root.crt
    │   │       └── client.root.key
    │   └── node
    │       ├── ca.crt
    │       ├── node.crt
    │       └── node.key
    └── data

Client certificates are created for the database users root, records_politeiad,
and records_politeiawww.  records_politeiad and records_politeiawww are the
politeiad and politeiawww users for the records cache.  Each client directory
contains all of the certificates required to connect to the database with that
user.  The root user is used to setup the CockroachDB databases in the
`cachesetup.sh` script below and for opening up a sql shell to run database
commands manually.

The node directory contains the certificates for running a CockroachDB
instance locally.  Directions for generating node certificates when deploying a
CockroachDB cluster can be found in the [CockroachDB manual deployment
docs](https://www.cockroachlabs.com/docs/stable/manual-deployment.html).

You can now start CockroachDB using the command below.  Politeia requires that
CockroachDB be running.

    cockroach start \
      --certs-dir=${HOME}/.cockroachdb/certs/node \
      --listen-addr=localhost \
      --store=${HOME}/.cockroachdb/data

Once CockroachDB is running, you can setup the cache databases and users using
the commands below.  We use the CockroachDB root user to set everything up.

    cd $GOPATH/src/github.com/decred/politeia
    ./cachesetup.sh ~/.cockroachdb/certs/clients/root

The database setup is now complete.  If you want to run database commands
manually you can do so by opening a sql shell.

    cockroach sql \
      --certs-dir=${HOME}/.cockroachdb/certs/clients/root \
      --host localhost

#### 4a. Setup cms database:

    cd $GOPATH/src/github.com/decred/politeia
    ./cmscerts.sh ~/.cockroachdb

    cockroach start \
      --certs-dir=${HOME}/.cockroachdb/certs/node \
      --listen-addr=localhost:26258 \
      --store=${HOME}/.cmsdb/data \
      --http-addr=localhost:8081

    cd $GOPATH/src/github.com/decred/politeia
    ./cmssetup.sh ~/.cockroachdb/certs/clients/root
    

#### 5. Build the programs:

Go 1.11 introduced [modules](https://github.com/golang/go/wiki/Modules), a new
dependency management approach, that obviates the need for third party tooling
such as `dep`.

Usage is simple and nothing is required except Go 1.11. If building in a folder
under `GOPATH`, it is necessary to explicitly build with modules enabled:

```
cd $GOPATH/src/github.com/decred/politeia
export GO111MODULE=on
go install -v ./...
```

If building outside of `GOPATH`, modules are automatically enabled, and `go
install` is sufficient.

```
go install -v ./...
```

The go tool will process the source code and automatically download
dependencies. If the dependencies are configured correctly, there will be no
modifications to the `go.mod` and `go.sum` files.

#### 6. Start the politeiad server by running on your terminal:

    politeiad

#### 7. Download politeiad's identity to politeiawww:

    politeiawww --fetchidentity

Accept politeiad's identity by pressing <kbd>Enter</kbd>.

The result should look something like this:

```
2018-08-01 22:48:48.468 [INF] PWWW: Identity fetched from politeiad
2018-08-01 22:48:48.468 [INF] PWWW: Key        : 331819226de0270d0c997749ce9f2b56bc5aed110f57faef8d381129e7ee6d26
2018-08-01 22:48:48.468 [INF] PWWW: Fingerprint: MxgZIm3gJw0MmXdJzp8rVrxa7REPV/rvjTgRKefubSY=
2018-08-01 22:48:48.468 [INF] PWWW: Save to /Users/<username>/Library/Application Support/Politeiawww/identity.json or ctrl-c to abort

2018-08-01 22:49:53.929 [INF] PWWW: Identity saved to: /Users/<username>/Library/Application Support/Politeiawww/identity.json
```

#### 8. Start the politeiawww server by running on your terminal:

    politeiawww

**Awesome!** Now you have your Politeia servers up and running!

At this point, you can:

* Follow the instructions at [decred/politeiagui](https://github.com/decred/politeiagui)
to setup Politeia and access it through the UI.
* Use the [politeiawwwcli](https://github.com/decred/politeia/tree/master/politeiawww/cmd/politeiawwwcli) tool to interact with politeiawww.
* Use the [politeia](https://github.com/decred/politeia/tree/master/politeiad/cmd/politeia) tool to interact directly with politeiad.
* Use any other tools or clients that are listed above.


### Further information

#### Paywall

This politeiawww feature prevents users from submitting new proposals and
comments until a payment in DCR has been paid. By default, it needs a
transaction with 2 confirmations to accept the payment.

Setting up the paywall requires a master public key for an account to
derive payment addresses.  You may either use one of the pre-generated test
keys (see [`sample-politeiawww.conf`](https://github.com/decred/politeia/blob/master/politeiawww/sample-politeiawww.conf))
or you may acquire one by creating accounts and retrieving the public keys
for those accounts:

Put the result of the following command as `paywallxpub=tpub...` in
`politeiawww.conf`:

```
dcrctl --wallet --testnet createnewaccount politeiapayments
dcrctl --wallet --testnet getmasterpubkey politeiapayments
```

If running with paywall enabled on testnet, it's possible to change the
minimum blocks required for accept the payment by setting `minconfirmations`
flag for politeiawww:

    politeiawww --minconfirmations=1


##### Paywall with politeiawww_refclient

When using politeiawww_refclient, the `-use-paywall` flag is true by default. When running the refclient without the paywall, set `-use-paywall=false`, but note that it will not be possible to test new proposals and comments or the `admin` flag.

* To test the admin flow:
 * Run the refclient once with paywall enabled and make the payment.
 * Stop politeiawww.
 * Set the user created in the first refclient execution as admin with politeiawww_dbutil.
 * Run refclient again with the `email` and `password` flags set to the user created in the first refclient execution.

#### Rebuilding the Cache

The cache will be built automatically on initial startup of politeiad and when
the cache version has changed, but there may also be times during development
that you want to force the cache to rebuild.  You can do this by using the
`--buildcache` flag when starting `politeiad`.  This will drop all current
tables from the cache, re-create the tables, then populate the cache with the
data that is in the politeiad git repositories.

## Integrated Projects / External APIs / Official URLs

* https://faucet.decred.org - instance of [testnetfaucet](https://github.com/decred/testnetfaucet)
  which is used by **politeiawww_refclient** to satisfy paywall requests in an
  automated fashion.

* https://test-proposals.decred.org/ - testing/development instance of Politeia.

* https://pi-staging.decred.org/ - politeia staging environment.

* https://proposals.decred.org/ - live production instance of Politeia.

## Library and interfaces

* `politeiad/api/v1` - JSON REST API for politeiad clients.
* `politeiawww/api/v1` - JSON REST API for politeiawww clients.
* `util` - common used miscellaneous utility functions.

## Misc

#### nginx reverse proxy sample (testnet)

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
