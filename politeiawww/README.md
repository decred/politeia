politeiawww
====

## Installing and running

### Install dependencies

<details><summary><b>Go 1.15 or 1.16</b></summary>

  Installation instructions can be at https://golang.org/doc/install.
  Ensure Go was installed properly and is a supported version:
  ```
  $ go version
  $ go env GOROOT GOPATH
  ```
  NOTE: `GOROOT` and `GOPATH` must not be on the same path. Since Go 1.8
  (2016), `GOROOT` and `GOPATH` are set automatically, and you do not need to
  change them. However, you still need to add `$GOPATH/bin` to your `PATH` in
  order to run binaries installed by `go get` and `go install` (On Windows,
  this happens automatically).

  Unix example -- add these lines to .profile:

  ```
  PATH="$PATH:/usr/local/go/bin"  # main Go binaries ($GOROOT/bin)
  PATH="$PATH:$HOME/go/bin"       # installed Go projects ($GOPATH/bin)
  ```

</details>

<details><summary><b>Git</b></summary>

  Installation instructions can be found at https://git-scm.com or
  https://gitforwindows.org.
  ```
  $ git version
  ```

</details>

### Install politeia

This step downloads and installs the politeiad and politeiawww binaries. This
can be skipped if you already completed it while setting up politeiad.

    ```
    $ mkdir -p $GOPATH/src/github.com/decred
    $ cd $GOPATH/src/github.com/decred
    $ git clone git@github.com:decred/politeia.git
    $ cd politeia
    $ go install -v ./...
    ```

### Setup MySQL (optional)

This repo includes a script to setup a MySQL user database, it creates the 
needed databases, the politeiawww user and assigns user privileges. Password 
authentication is used for all database connections.

**Note:** This is an optional step. By default, politeiawww will use a LevelDB 
instance that does not require any additional setup.

The setup script assumes MySQL is running on localhost:3306 and the users will 
be accessing the databse from localhost. See the setup script comments for more 
complex setups.

Run the following commands. You will need to replace rootpass with the existing 
password of your root user. The politeiawwwpass is the password that will be 
set for the politeiawww user when it's created.

```
$ cd $GOPATH/src/github.com/decred/politeia/politeiawww/scripts/userdb
$ env \
  MYSQL_ROOT_PASSWORD=rootpass \
  MYSQL_POLITEIAWWW_PASSWORD=politeiawwwpass \
  ./mysqlsetup.sh
```

You will need to use the `--userdb=mysql` flag when starting politeiawww or 
add `userdb=mysql` to the `politeiawww.config` file that is setup in the steps
below.

Also, an encryption key is required when using a MySQL database, use
`politeiawww_dbutil` cmd tool to create one: 
```
politeiawww_dbutil -createkey 
```

### Setup and run politeiawww

[politeiad](https://github.com/decred/politeia/tree/master/politeiad#politeiad)
must already be setup and running before you attempt to run politeiawww.

1. Setup the politeiawww configuration file.

   [`sample-politeiawww.conf`](https://github.com/decred/politeia/blob/master/politeiawww/sample-politeiawww.conf)

   Copy the sample configuration file to the politeiawww app data directory.
   The app data directory will depend on your OS.

   * **macOS**

     `/Users/<username>/Library/Application Support/Politeiawww/politeiawww.conf`

   * **Windows**

     `C:\Users\<username>\AppData\Local\Politeiawww/politeiawww.conf`

   * **Unix**

     `~/.politeiawww/politeiawww.conf`

    ``` 
    $ mkdir -p ${HOME}/.politeiawww/
    $ cd $GOPATH/src/github.com/decred/politeia/politeiawww
    $ cp ./sample-politeiawww.conf ${HOME}/.politeiawww/politeiawww.conf
    ```

    Use the following config settings to spin up a development politeiawww
    instance.

   **politeiawww.conf**

    ```
    ; politeiad host and auth credentials
    rpchost=127.0.0.1
    rpcuser=user
    rpcpass=pass
    rpccert=~/.politeiad/https.cert

    testnet=true
    ```
    **Pi configuration**

    Pi, Decred's proposal system, requires adding the following additional
    settings to your configuration file.  

    ```
    ; Uncomment to enable paywall (optional)
    ; paywallxpub=tpubVobLtToNtTq6TZNw4raWQok35PRPZou53vegZqNubtBTJMMFmuMpWybFCfweJ52N8uZJPZZdHE5SRnBBuuRPfC5jdNstfKjiAs8JtbYG9jx
    ; paywallamount=10000000
    ```

2. Start up politeiawww.

    ```
    $ politeiawww
    ```
    
    if politeiawww requires --fetchidentity flag
    
    ```
    $ politeiawww --fetchidentity
    ```
    
## API

The [politeiawww APIs](https://github.com/decred/politeia/tree/master/politeiawww/api/)
and [politeiawww client](https://github.com/decred/politeia/tree/master/politeiawww/client)
can be treated as stable. All other APIs and libraries should be treated as
unstable and subject to breaking changes.


## Tools and reference clients

* [politeiavoter](https://github.com/decred/politeia/tree/master/politeiawww/cmd/politeiavoter) - 
  Tool for voting on Decred proposals using DCR tickets.
* [politeiaverify](https://github.com/decred/politeia/tree/master/politeiawww/cmd/politeiaverify) - 
  Tool for verifying data and timestamps downloaded from politeiagui.
* [politeiawww_dbutil](https://github.com/decred/politeia/tree/master/politeiawww/cmd/politeiawww_dbutil) - 
  Tool for making manual changes to the user database.
* [piclt](https://github.com/decred/politeia/tree/master/politeiawww/cmd/pictl) -
  Reference client for pi, Decred's proposal system.

