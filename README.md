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

See the politeiad [README](https://github.com/decred/politeia/tree/master/politeiad#politeiad) for instructions on building and running politeiad.  

See the politeiawww [README](https://github.com/decred/politeia/tree/master/politeiawww#politeiawww) for instructions on building and running politeiawww.  
