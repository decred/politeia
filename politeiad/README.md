politeiad
====

# Installing and running

## Install Dependencies

<details><summary><b>Go 1.14 or 1.15</b></summary>

  Installation instructions can be found here: https://golang.org/doc/install.  
  Ensure Go was installed properly and is a supported version:  

  ```sh
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
  ```sh
  $ git version
  ```
</details>

## Build from source

1. Install MariaDB or MySQL. Make sure to setup a password for the root user.

2. Update the MySQL max connections settings.

   Max connections defaults to 151 which is not enough for trillian. You will
   be prompted for the MySQL root user's password when running these commands.

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

3. Install trillian v1.3.13.

    ```
    $ mkdir -p $GOPATH/src/github.com/google/
    $ cd $GOPATH/src/github.com/google/
    $ git clone git@github.com:google/trillian.git
    $ cd trillian
    $ git checkout tags/v1.3.13 -b v1.3.13
    $ go install -v ./...
    ```

4. Install politeia.

    ```
    $ mkdir -p $GOPATH/src/github.com/decred
    $ cd $GOPATH/src/github.com/decred
    $ git clone git@github.com:decred/politeia.git
    $ cd politeia
    $ go install -v ./...
    ```

5. Run the politeiad mysql setup scripts.

   This will create the politeiad and trillian users as well as creating the
   politeiad databases. Trillian does not support SSL authentication to the
   MySQL instance. Password authentication must be used.

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
      ./mysql-tstore-setup.sh
    ```

6. Run the trillian mysql setup scripts.

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

7. Start up the trillian instances.

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

8. Setup the politeiad configuration file.

   [`sample-politeiad.conf`](https://github.com/decred/politeia/blob/master/politeiad/sample-politeiad.conf)

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
    instance. You'll need to replace the `politeiadpass` with the password
    you created for your politeiad MySQL user.

   **politeiad.conf**

    ```
    rpcuser=user
    rpcpass=pass
    testnet=true

    ; Tstore settings
    dbtype=mysql

    ; Pi plugin configuration
    plugin=pi
    plugin=comments
    plugin=dcrdata
    plugin=ticketvote
    plugin=usermd
    ```

9. Start up the politeiad instance. The password for the politeiad user must
   be provided in the `DBPASS` env variable.

    ```
    $ env DBPASS=politeiadpass politeiad
    ```

# Tools and reference clients

* [politeia](https://github.com/decred/politeia/tree/master/politeiad/cmd/politeia) - Reference client for politeiad.


