# cmswww

cmswww is a command line tool that allows you to interact with the cmswww API.

## Available Commands
You can view the available commands and application options by using the help
flag.

    $ cmswww -h 

You can view details about a specific command, including required arguments,
by using the help command.

    $ cmswww help <command>

## Persisting Data Between Commands
cmswww stores  user identity data (the user's public/private key pair), session
cookies, and CSRF tokens in the cmswww directory.  This allows you to login
with a user and use the same session data for subsequent commands.  The data is
segmented by host, allowing you to login and interact with multiple hosts
simultaneously.

The location of the cmswww directory varies based on your operating system.

**macOS**

`/Users/<username>/Library/Application Support/Cmswww`

**Windows**

`C:\Users\<username>\AppData\Local\Cmswww`

**Ubuntu**

`~/.cmswww`

## Setup Configuration File
cmswww has a configuration file that you can setup to make execution easier.
You should create the configuration file under the following paths.

**macOS**

`/Users/<username>/Library/Application Support/Piwww/cmswww.conf`

**Windows**

`C:\Users\<username>\AppData\Local\Piwww/cmswww.conf`

**Ubuntu**

`~/.cmswww/cmswww.conf`

If you're developing locally, you'll want to set the politeiawww host in the
configuration file since the default politeiawww host is
`https://proposals.decred.org`.  Copy these lines into your `cmswww.conf` file.
`skipverify` is used to skip TLS certificate verification and should only be
used when running politeia locally.

```
host=https://127.0.0.1:4443
skipverify=true
```


