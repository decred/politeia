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
```

Example:

```
politeiawww_dataload --setadmin user@example.com true
```
