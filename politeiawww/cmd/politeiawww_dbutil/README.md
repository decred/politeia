# politeiawww_dbutil

politeiawww_dbutil is a tool that allows you to interact with the politeiawww
database. 
**Note**: The politeiawww database works with LevelDB and CockroachDB. 
If you are using LevelDB you have to shut down politeiawww before using this tool.


## Available Commands
You can view the available commands and application options by using the help
flag.

`$ politeiawww_dbutil -h`

You can view details about a specific command, including required arguments,
by putting the help flag after the command.

`$ politeiawww_dbutil <command> -h`


## Setup Configuration File
politeiawww_dbutil has a configuration file that you can setup to make execution
easier. You should create the configuration file under the following paths.

**macOS**

```
/Users/<username>/Library/Application Support/Politeiawww/dbutil/politeiawww_dbutil.conf
```

**Windows**

```
C:\Users\<username>\AppData\Local\Politeiawww/cli/politeiawww_dbutil.conf
```

**Ubuntu**

```
~/.politeiawww/cli/politeiawww_dbutil.conf
```

Check the sample configuration file at `politeiawww_dbutil/sample-politeaiwww.conf`
for more information.



## Usage 


### Migrating the database 

If you are running an older version of the database you need to migrate
it to the most recent db version:
`politeiawww_dbutil migrate`

### Dumping the database

Dumping is useful for saving a snapshot of the database at a given point in time.
The database can be recreated from the snapshot later:

`politeiawww_dbutil dump dir/where/to/save/the/dump`

### Importing the database

Importing is useful for restoring the database from a snapshot. This can be used
for switching the database implementations (e.g from leveldb to cockroachdb):

`politeiawww_dbutil import where/is/dump.json`

### Set admin 

Set admin allows to upgrade or downgrade a user access level:

`politeiawww_dbutil setadmin <user_id> <true/false>`

### Add credits

Add Credits allows to add credits to a user's account:

`politeiawww_dbutill addcredits <user_id> <amount>`

### Db Version

The `dbversion` command prints the current version of the database:

`politeiawww_dbutill dbversion`

## Examples

### Migrating from an unencrypted leveldb to a encrypted cockroachdb

1. The first thing to be done is to migrate the database to make sure
leveldb is up to date with the latest version of the database.
The only required configuration here is the data directory. 

`politeiawww_dbutil --datadir="~/.politeiawww/data" migrate`

2. Then we need to dump the database into a directory. This will 
save a snapshot form the database which will be used later to
restore the data into cockroachdb.

`politeiawww_dbutil --datadir="~/.politeiawww/data" dump ~/.politeiawww/dbutil/`

This command will save the dump file under  `~/.politeiawww/dbutil/dump.json`.

3. Now we switch the database option and turn on the encryption.
Make sure the cockroachdb configurations are specified. Its convenient 
to set the configuration options into your configuration file, like so:

```
encryptdb=true
dbkeyfilename=~/.politeiawww/dbkey.json
database=cockroachdb
dbhost=localhost:26257
dbrootcert=~/.cockroachdb/certs/ca.crt
dbcertdir=~/.cockroachdb/certs
```

4. Run `politeiawww` with this configuration so the database can be created.

**Note:** if you don't have a database key yet, you can generate one by running:
`politeiawww --createdbkey`


5. Make sure the database is running in the specified host and run:

`politeiawww_dbutil import ~/.politeiawww/dbutil/dump.json`

if everything goes well you should see the message:
`Database successfully imported!`

