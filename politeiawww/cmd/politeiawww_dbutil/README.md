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
      -mysql
            Use MySQL

    Application options
      -testnet
            Use testnet database
      -datadir string
            politeiawww data directory
            (default osDataDir/politeiawww/data)
      -cockroachdbhost string
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
            File containing the CockroachDB/MySQL encryption key
            (default osDataDir/politeiawww/sbox.key)
      -password string
            MySQL database password.
      -mysqlhost string
            MySQL ip:port 
            (default localhost:3306)

    Commands
      -addcredits
            Add proposal credits to a user's account
            Required DB flag : -leveldb, -cockroachdb or -mysql
            LevelDB args     : <email> <quantity>
            CockroachDB args : <username> <quantity>
      -setadmin
            Set the admin flag for a user
            Required DB flag : -leveldb, -cockroachdb or -mysql
            LevelDB args     : <email> <true/false>
            CockroachDB args : <username> <true/false>
      -setemail
            Set a user's email to the provided email address
            Required DB flag : -cockroachdb or -mysql
            CockroachDB args : <username> <email>
      -stubusers
            Create user stubs for the public keys in a politeia repo
            Required DB flag : -leveldb, -cockroachdb or -mysql
            LevelDB args     : <importDir>
            CockroachDB args : <importDir>
      -dump
            Dump the entire database or the contents of a specific user
            Required DB flag : -leveldb
            LevelDB args     : <username>
      -createkey
            Create a new encryption key that can be used to encrypt data at rest
            Required DB flag : None
            Args             : <destination (optional)>
                               (default osDataDir/politeiawww/sbox.key)
      -migrate
            Migrate from one user database to another
            Required DB flag : None
            Args             : <fromDB> <toDB>
                               Valid DBs are mysql, cockroachdb, leveldb
      -verifyidentities
            Verify a user's identities do not violate any politeia rules. Invalid
            identities are fixed.
            Required DB flag : -cockroachdb or -mysql 
            Args             : <username>
      -resettotp
            Reset a user's totp settings in case they are locked out and 
            confirm identity. 
            Required DB flag : -leveldb, -cockroachdb or -mysql
            LevelDB args     : <email>
            CockroachDB args : <username>

### Examples

Mainnet example:

    $ politeiawww_dbutil -cockroachdb -setadmin username true

Testnet example:

    $ politeiawww_dbutil -testnet -cockroachdb -setadmin username true

### Migrate user database

The `-migrate` command allows you to migrate from one database type to another. 

**Notes:**
 - CockroachDB & MySQL encrypt data at rest so if you migrating from levelDB 
 you will first need to create an encryption key using the `-createkey` command.  

 - The flags `-datadir`, `-cockroachdbhost`, `-rootcert`, `-clientcert`, 
 `-clientkey`, `-encryptionkey` and `mysqlhost` only need to be set if they 
 deviate from the defaults.

Create an encryption key.

    $ politeiawww_dbutil -createkey
    Encryption key saved to: ~/.politeiawww/sbox.key

Migrate the user database.

    $ politeiawww_dbutil -testnet -password grrr -migrate cockroachdb mysqldb 
    CockroachDB : localhost:26257 testnet3 
    MySQLDB : localhost:3306 testnet3
    Migrating records from cockroachdb to mysqldb...
    Users migrated : 1
    Paywall index  : 0
    Done!

Update your politeiawww.conf file.  The location of the encryption key may
differ depending on your operating system.

    userdb=mysql
    encryptionkey=~/.politeiawww/sbox.key

### Stubbing Users

If you import data from a public politeia repo using the
[politeiaimport](https://github.com/decred/politeia/tree/master/politeiad/cmd/politeiaimport)
tool, you will also need to create user stubs in the politeiawww database for
the public keys found in the import data.  Without the user stubs, politeiawww
won't be able to associate the public keys with specific user accounts and will
error out.
