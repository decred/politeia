# Kamona

**Kamona is a fork from politeia the decred proposal system.** kamona is a system to create crowdfundings and/or funding open sources projects in a translucent way. Every data is stored and anchored into Decred’s blockchain making it clear to fund your idea. 

The kamona stack is as follows:
```
~~~~~~~~ Internet ~~~~~~~~~
            |
+-------------------------+
|      kamona www       |
+-------------------------+
            |
+-------------------------+
|        kamonad        |
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
* kamonad - Reference server daemon.
* kamonawww - Web backend server; depends on kamonad.

## Development
#### 1. Install [Go](https://golang.org/doc/install), [dep](https://github.com/golang/dep), and [Git](https://git-scm.com/downloads).
Make sure each of these are in the PATH.
#### 2. Clone this repository.
#### 3. Setup configuration files:
kamonad and kamonawww both have configuration files that you should
set up to make execution easier. You should create the configuration files
under the following paths:
* **macOS**
   ```
   /Users/<username>/Library/Application Support/Kamonad/kamonad.conf
   /Users/<username>/Library/Application Support/Kamonawww/kamonawww.conf
   ```
* **Windows**
   ```
   C:\Users\<username>\AppData\Local\Kamonad/kamonad.conf
   C:\Users\<username>\AppData\Local\Kamonawww/kamonawww.conf
   ```
* **Ubuntu**
   ```
   ~/.kamonad/kamonad.conf
   ~/.kamonawww/kamonawww.conf
   ```
Copy and change the [`sample-politeiawww.conf`](https://github.com/decred/politeia/blob/master/politeiawww/sample-politeiawww.conf)
and [`sample-politeiad.conf`](https://github.com/decred/politeia/blob/master/politeiad/sample-politeiad.conf) files.
You can also use the following default configurations:

**kamonad.conf**:

    rpcuser=user
    rpcpass=pass
    testnet=true

**kamonawww.conf**:

    rpchost=127.0.0.1
    rpcuser=user
    rpcpass=pass
    rpccert="/Users/<username>/Library/Application Support/Kamonad/https.cert"
    testnet=true
