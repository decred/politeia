# politeiawww_dbutil

politeiawww_dbutil is a tool that allows you to interact with the politeiawww
database.

**Note**: You currently have to shut down politeiawww before using this tool.


## Usage

You can specify the following options:

```
    --testnet
    Whether to interact with the testnet or mainnet database

    --datadir <dir>
    Specify a different directory where the database is stored

    --dump [email]
    Print the contents of the entire database to the console, or the
    contents of the user, if provided.

    --setadmin <email> <true/false>
    Sets or removes the given user as admin.

    --addcredits <email> <quantity>
    Adds proposal credits to the given user.

  -stubusers <importdir>
        Create user stubs for the public keys in a politeia repo.
```

Example:

```
politeiawww_dataload --setadmin user@example.com true
```

### Stubbing Users

If you import data from a public politeia repo using the
[politeiaimport](https://github.com/decred/politeia/tree/master/politeiad/cmd/politeiaimport)
tool, you will also need to create user stubs in the politeiawww database for
the public keys found in the import data.  Without the user stubs, politeiawww
won't be able to associate the public keys with specific user accounts, which
will cause errors.
