politeia
====

[![Build Status](https://github.com/decred/politeia/workflows/Build%20and%20Test/badge.svg)](https://github.com/decred/politeia/actions)
[![ISC License](https://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)
[![Go Report Card](https://goreportcard.com/badge/github.com/decred/politeia)](https://goreportcard.com/report/github.com/decred/politeia)

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
|      politeiawww        |
+-------------------------+
            |
+-------------------------+
|        politeiad        |
+-------------------------+
            |
~~~~~~~~ Internet ~~~~~~~~~
            |
+-------------------------+
|        dcrtimed         |
+-------------------------+
```

Core software:

* politeiad - Reference server daemon. Data layer.
* politeiawww - Web backend server; depends on politeiad. User layer.

# Installing and running

## Install dependencies

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

See the politeiad instructions for [building from
source](https://github.com/decred/politeia/tree/master/politeiad#build-from-source).

See the politeiawww instructions for [building from
source](https://github.com/decred/politeia/tree/master/politeiawww#build-from-source).
