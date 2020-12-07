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

## Setup configuration file

[`sample-politeiad.conf`](https://github.com/decred/politeia/blob/master/politeiad/sample-politeiad.conf)

Copy the sample configuration file to the politeiad data directory for your OS.

* **macOS**

   `/Users/<username>/Library/Application Support/Politeiad/politeiad.conf`

* **Windows**

   `C:\Users\<username>\AppData\Local\Politeiad/politeiad.conf`

* **Ubuntu**

   `~/.politeiad/politeiad.conf`

Use the following config settings to spin up a development politeiad instance.

**politeiad.conf**:

    rpcuser=user
    rpcpass=pass
    testnet=true

# Tools and reference clients

* [politeia](https://github.com/decred/politeia/tree/master/politeiad/cmd/politeia) - Reference client for politeiad.


