# politeiawww_dbutil

politeiawww_dbutil is a tool that allows you to interact with the politeiawww
database.

**Note**: If you are using LevelDB for the user database you have to shut down
politeiawww before using this tool.  LevelDB only allows for a single
connection at a time.


## Usage

You can specify the following options:

    Database options
      -leveldb
            Use LevelDB
      -cockroachdb
            Use CockroachDB

    Application options
      -testnet
            Use testnet database
      -datadir string
            politeiawww data directory
            (default osDataDir/politeiawww/data)
      -host string
            CockroachDB ip:port 
            (default localhost:26257)
      -rootcert string
            File containing the CockroachDB SSL root cert
            (default ~/.cockroachdb/certs/clients/politeiawww/ca.crt)
      -clientcert string
            File containing the CockroachDB SSL client cert
            (default ~/.cockroachdb/certs/clients/politeiawww/client.politeiawww.crt)
      -clientkey string
            File containing the CockroachDB SSL client cert key
            (default ~/.cockroachdb/certs/clients/politeiawww/client.politeiawww.key)
      -encryptionkey string
            File containing the CockroachDB encryption key
            (default osDataDir/politeiawww/sbox.key)

    Commands
      -addcredits
            Add proposal credits to a user's account
            Required DB flag : -leveldb or -cockroachdb
            LevelDB args     : <email> <quantity>
            CockroachDB args : <username> <quantity>
      -setadmin
            Set the admin flag for a user
            Required DB flag : -leveldb or -cockroachdb
            LevelDB args     : <email> <true/false>
            CockroachDB args : <username> <true/false>
      -stubusers
            Create user stubs for the public keys in a politeia repo
            Required DB flag : -leveldb or -cockroachdb
            LevelDB args     : <importDir>
            CockroachDB args : <importDir>
      -dump
            Dump the entire database or the contents of a specific user
            Required DB flag : -leveldb
            LevelDB args     : <email>
      -createkey
            Create a new encryption key that can be used to encrypt data at rest
            Required DB flag : None
            Args             : <destination (optional)>
                               (default osDataDir/politeiawww/sbox.key)
      -migrate
            Migrate a LevelDB user database to CockroachDB
            Required DB flag : None
            Args             : None

     -verifyidentities
          Verify a user's identities do not violate any politeia rules. Invalid
          identities are fixed.
          Required DB flag : -cockroachdb
          Args             : <username>

### Examples

Mainnet example:

    $ politeiawww_dbutil -cockroachdb -setadmin username true

Testnet example:

    $ politeiawww_dbutil -testnet -cockroachdb -setadmin username true

### Migrate from LevelDB to CockroachDB

The `-migrate` command allows you to migrate a LevelDB instance to CockroachDB.
CockroachDB encrypts data at rest so you will first need to create an
encryption key using the `-createkey` command.  The flags `-datadir`, `-host`,
`-rootcert`, `-clientcert`, `-clientkey`, and `-encryptionkey` only need to be
set if they deviate from the defaults.

Create an encryption key.

    $ politeiawww_dbutil -createkey
    Encryption key saved to: ~/.politeiawww/sbox.key

Migrate the user database.

    $ politeiawww_dbutil -migrate
    LevelDB     : ~/.politeiawww/data/mainnet/users
    CockroachDB : localhost:26257 mainnet
    Migrating records from LevelDB to CockroachDB...
    Users migrated : 6
    Paywall index  : 5
    Done!

Update your politeiawww.conf file.  The location of the encryption key may
differ depending on your operating system.

    userdb=cockroachdb
    encryptionkey=~/.politeiawww/sbox.key

### Stubbing Users

If you import data from a public politeia repo using the
[politeiaimport](https://github.com/thi4go/politeia/tree/master/politeiad/cmd/politeiaimport)
tool, you will also need to create user stubs in the politeiawww database for
the public keys found in the import data.  Without the user stubs, politeiawww
won't be able to associate the public keys with specific user accounts and will
error out.
