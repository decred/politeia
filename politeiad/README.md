politeiad
====

## Installing and running

### Install dependencies

<details><summary><b>Go 1.17</b></summary>

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

<details><summary><b>MySQL/MariaDB</b></summary>

  Installation instructions can be found at the links below.  
  MySQL: https://www.mysql.com  
  MariaDB: https://mariadb.com  

  Unix example:  

  ```
  $ sudo apt install mariadb-server
  ```

  Run the security script to configure MariaDB. You MUST set a password for
  the root user. The politeiad scripts will not run properly if the root user
  does not have a password.  

  ```
  $ sudo mysql_secure_installation
  ```

  Update the max connections setting. This is required for politeiad to run
  properly. You will be prompted for the MySQL root user's password when
  running these commands.  

  ```
  # Update max connections    
  $ mysql -u root -p -e "SET GLOBAL max_connections = 2000;"

  # Verify the setting
  $ mysql -u root -p -e "SHOW VARIABLES LIKE 'max_connections';"
  ```

  You can also update the config file so you don't need to set it manually in
  the future.  Make sure to restart MySQL once you update the config file.  

  MariaDB config file: `/etc/mysql/mariadb.cnf`  
  MySQL config file: `/etc/mysql/my.cnf`  

  ```
  [mysqld]
  max_connections = 2000
  ```

</details>

<details><summary><b>Trillian 1.4.0</b></summary>

  Installation instructions can be found at https://github.com/google/trillian.

  Unix example:

  ```
  $ mkdir -p $GOPATH/src/github.com/google/
  $ cd $GOPATH/src/github.com/google/
  $ git clone git@github.com:google/trillian.git
  $ cd trillian
  $ git checkout tags/v1.4.0 -b v1.4.0
  $ go install -v ./...
  ```

</details>

### Install politeia

This step downloads and installs the politeiad and politeiawww binaries.  

You must have all dependencies installed before continuing. The MySQL/MariaDB
root user must have a password and the max connections setting must be updated.
See the MySQL/MariaDB installation section for more details.

  ```
  $ mkdir -p $GOPATH/src/github.com/decred
  $ cd $GOPATH/src/github.com/decred
  $ git clone git@github.com:decred/politeia.git
  $ cd politeia
  $ go install -v ./...
  ```

### Setup and run politeiad

1. Run the politeiad mysql setup scripts.

   This will create the politeiad and trillian users as well as creating the
   politeiad databases. Password authentication is used for all database
   connections.

   **The password that you set for the politeiad MySQL user will be used to
   derive an encryption key that is used to encrypt non-public data at rest.
   Make sure to setup a strong password when running in production. Once set,
   the politeiad user password cannot change.**

   The setup script assumes MySQL is running on `localhost:3306` and the users
   will be accessing the databse from `localhost`. See the setup script
   comments for more complex setups.

   Run the following commands. You will need to replace `rootpass` with the
   existing password of your root user. The `politeiadpass` and `trillianpass`
   are the password that will be set for the politeiad and trillian users when
   the script creates them.

    ```
    $ cd $GOPATH/src/github.com/decred/politeia/politeiad/scripts
    $ env \
      MYSQL_ROOT_PASSWORD=rootpass \
      MYSQL_POLITEIAD_PASSWORD=politeiadpass \
      MYSQL_TRILLIAN_PASSWORD=trillianpass \
      ./tstore-mysql-setup.sh
    ```

2. Run the trillian mysql setup scripts.

   These can only be run once the trillian MySQL user has been created in the
   previous step.

   The `trillianpass` and `rootpass` will need to be updated to the passwords
   for your trillian and root users.

   If setting up a mainnet instance, change the `MYSQL_DATABASE` env variable
   to `mainnet_trillian`.

    ```
    $ cd $GOPATH/src/github.com/google/trillian/scripts

    # Testnet setup
    $ env \
      MYSQL_USER=trillian \
      MYSQL_PASSWORD=trillianpass \
      MYSQL_DATABASE=testnet3_trillian \
      MYSQL_URI="${MYSQL_USER}:${MYSQL_PASSWORD}@tcp(127.0.0.1:3306)/${MYSQL_DATABASE}" \
      MYSQL_ROOT_PASSWORD=rootpass \
      ./resetdb.sh
    ```

3. Start up trillian.

   Running trillian requires running a trillian log server and a trillian log
   signer. These are seperate processes that will be started in this step. 

   You will need to replace the `trillianpass` with the trillian user's
   password that you setup in previous steps. The commands below for testnet
   and mainnet run the trillian instances on the same ports so you can only
   run one set of commands, testnet or mainnet. Run the testnet commands if
   you're setting up a development environment.

   If setting up a mainnet instance, change the `MYSQL_DATABASE` env variable
   to `mainnet_trillian` for both the log server and log signer.


   Start testnet log server
    ```
    $ export MYSQL_USER=trillian && \
      export MYSQL_PASSWORD=trillianpass && \
      export MYSQL_DATABASE=testnet3_trillian && \
      export MYSQL_URI="${MYSQL_USER}:${MYSQL_PASSWORD}@tcp(127.0.0.1:3306)/${MYSQL_DATABASE}"

    $ trillian_log_server \
      --mysql_uri=${MYSQL_URI} \
      --mysql_max_conns=2000 \
      --rpc_endpoint localhost:8090 \
      --http_endpoint localhost:8091 \
      --logtostderr ...
    ```

   Start testnet log signer
    ```
    $ export MYSQL_USER=trillian && \
      export MYSQL_PASSWORD=trillianpass && \
      export MYSQL_DATABASE=testnet3_trillian && \
      export MYSQL_URI="${MYSQL_USER}:${MYSQL_PASSWORD}@tcp(127.0.0.1:3306)/${MYSQL_DATABASE}"

    $ trillian_log_signer --logtostderr --force_master \
      --batch_size=1000 \
      --sequencer_guard_window=0 \
      --sequencer_interval=200ms \
      --mysql_uri=${MYSQL_URI} \
      --rpc_endpoint localhost:8092 \
      --http_endpoint=localhost:8093 
    ```

4. Setup the politeiad configuration file.

   [`sample-politeiad.conf`](sample-politeiad.conf)

   Copy the sample configuration file to the politeiad app data directory. The
   app data directory will depend on your OS.

   * **macOS**

     `/Users/<username>/Library/Application Support/Politeiad/politeiad.conf`

   * **Windows**

     `C:\Users\<username>\AppData\Local\Politeiad/politeiad.conf`

   * **Unix**

     `~/.politeiad/politeiad.conf`

    ```
    $ mkdir -p ${HOME}/.politeiad/
    $ cd $GOPATH/src/github.com/decred/politeia/politeiad
    $ cp ./sample-politeiad.conf ${HOME}/.politeiad/politeiad.conf
    ```

    Use the following config settings to spin up a development politeiad
    instance.

   **politeiad.conf**

    ```
    ; politeiad settings
    rpcuser=user
    rpcpass=pass
    testnet=true

    ; tstore settings
    dbtype=mysql
    ```

    **Pi configuration**

    Pi, Decred's proposal system, requires adding the following additional
    settings to your configuration file.  

    ```
    ; Pi plugin configuration
    plugin=pi
    plugin=comments
    plugin=dcrdata
    plugin=ticketvote
    plugin=usermd
    pluginsetting=comments,allowextradata,1
    ```
5. Start up politeiad.

   The password for the politeiad MySQL user must be provided in the `DBPASS`
   env variable. The encryption key used to encrypt non-public data at rest
   will be derived from the `DBPASS`. The `DBPASS` cannot change.

   A password to derive the trillian signing key must be provided in the
   `TLOGPASS` env variable. This password has not been created yet. You can
   set it to whatever you want, but it cannot change once set.

   ```
   $ env DBPASS=politeiadpass TLOGPASS=tlogpass politeiad
   ```

## Politeiad API

- [politeiad API](api/v2)
- [politeiad client](client/)

The politeiad APIs and libraries should be treated as unstable and subject to
breaking changes.

## Plugins

The basic politeiad API allows users to submit and edit records, where a record
is an arbitrary set of files. A Decred proposal is an example of a record.

politeiad uses a plugin architecture to extend records with additional
functionality. For example, the comments plugin extends a record with comment
functionality. It provides an API for creating, editing, deleting, and
retrieving comments.

The plugins and their APIs can be found [here](plugins/).

Plugins can be specified using the `--plugin` flag or a `plugin` config file
entry.

Plugins have default settings that can be overridden using the
`--pluginsetting` flag or a `pluginsetting` config file entry. Plugin settings
are key-value settings that must use the format:

    pluginID,key,value

The list of settings for each plugin can be found in the [plugin
APIs](plugins/).

The following example shows what an entry in the politeiad config file would
look like if the user wanted to override the default comments plugin setting
for a maximum comment length. This would set the max comment length to 2500
characters.

    pluginsetting=comments,commentlengthmax,2500

Some plugin settings require multiple values to be provided. One such example
is when a list of supported characters is required. You can provide multiple
values for a single plugin setting by passing the values in an array. The
array must be a valid JSON encoded []string.

    # Easiest method
    pluginsetting=pluginID,key,["value1","value2","value3"]

    # Or you can manually escape the quotes
    pluginsetting="pluginID,key,[\"value1\",\"value2\",\"value3\"]"

## Tools and reference clients

* [politeia](cmd/politeia) - Reference client for politeiad.

## Development

### Reset databases

You can remove all records from politeiad using the following commands.

These commands will not delete any politeiawww user data. This lets you reset
the politeiad data to clear out all existing records while still keeping all of
your politeiawww user accounts intact so that you can have a fresh development
enviroment without needing to re-setup the user accounts.

  ```
  # Reset politeiad database
  $ cd ${HOME}/go/src/github.com/decred/politeia/
  $ env MYSQL_ROOT_PASSWORD="rootpass" \
    .politeiad/scripts/tstore-mysql-reset.sh

  # Reset trillian database
  $ cd ${HOME}/go/src/github.com/google/trillian/
  $ export MYSQL_USER=trillian && \
    export MYSQL_PASSWORD=trillianpass && \
    export MYSQL_DATABASE=testnet3_trillian && \
    export MYSQL_ROOT_PASSWORD=rootpass && \
    ./scripts/resetdb.sh

  # Reset cached data. The location of this directory will depend on your
  # operating system.
  rm -rf ~/.politeiad/data/testnet3
  ```
