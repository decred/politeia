pictl
====

pictl is a command line tool that allows you to interact with the politeiawww
API and has been configured to be a pi (Decred's proposal system) client.

# Available Commands
You can view the available commands and application options by using the help
flag.

    $ pictl -h 

You can view details about a specific command by using the help command.

    $ pictl help <command>

# Persisting Data Between Commands
pictl stores  user identity data (the user's public/private key pair), session
cookies, and CSRF tokens in the pictl directory.  This allows you to login with
a user and use the same session data for subsequent commands.  The data is
segmented by host, allowing you to login and interact with multiple hosts
simultaneously.

The location of the pictl directory varies based on your operating system.

**macOS**

`/Users/<username>/Library/Application Support/Pictl`

**Windows**

`C:\Users\<username>\AppData\Local\Pictl`

**Ubuntu**

`~/.pictl`

# Setup Configuration File
pictl has a configuration file that you can setup to make execution easier.
You should create the configuration file under the following paths.

**macOS**

`/Users/<username>/Library/Application Support/Pictl/pictl.conf`

**Windows**

`C:\Users\<username>\AppData\Local\Pictl/pictl.conf`

**Ubuntu**

`~/.pictl/pictl.conf`

If you're developing locally, you'll want to set the politeiawww host in the
configuration file to your local politeiawww instance. The host defaults to
`https://proposals.decred.org`.  Copy these lines into your `pictl.conf` file.
`skipverify` is used to skip TLS certificate verification and should only be
used when running politeia locally.

```
host=https://127.0.0.1:4443
skipverify=true
```

# Example Usage

## Create a new user

    $ pictl usernew email@example.com username password --verify --paywall

`--verify` and `--paywall` are options that can be used when running
politeiawww on testnet to make the user registration process quicker.

`--verify` will satisfy the email verification requirement for the user.

`--paywall` will use the Decred testnet faucet to satisfy the user registration
fee requirement. 

**If you use the `--paywall` flag, you will still need to wait for block
confirmations before you'll be allowed to submit proposals.**

## Login with the user

    $ pictl login email@example.com password

## Assign admin privileges and create proposal credits

Proposal credits are required in order to submit a proposal. They are a spam
prevention measure that would normally need to be purchased using DCR, but if
you're running politeiawww locally, you can use the politeiawww_dbutil tool to
add proposal credits to your account.  You'll also need to give your user admin
privileges if you want to be able make proposals public and to start the
proposal vote.

**You need to stop politeiawww in order to run these commands.  You'll
get a `resource temporarily unavailable` error if you don't.**

    $ politeiawww_dbutil -testnet -setadmin username true
    $ politeiawww_dbutil -testnet -addcredits username 50

**Start politeiawww back up.**

## Submit a new proposal

When submitting a proposal, you can either specify a markdown file or you can
use the `--random` flag to have pictl generate a random proposal for you.

    $ pictl proposalnew --random
    {
      "files": [
        {
          "name": "index.md",
          "mime": "text/plain; charset=utf-8",
          "digest": "2a72cd797f164489f18628a84b81604d91cb3dd9e8217e3f12c6ba37ab6b7760",
          "payload": "S0gycmxiZUJiVmJ4bTR0OEhwRWpQZGxEQlpXdUl1QkR4RjU3cXNZZXpFZz0KUnJJRmtqM2RYaTEwQW9GekZaKzd3QW9HVk5LVzVRWkZWUzNYWi9jbnJTWT0KQmYrcDY4YXN4NE1PWFk1WHl2a1RLTm1QdlM1bjdUcjZNQ0p5ZWdtZm1UVT0KMVNyWFp6Smh6VDBGd29LYnppdStBMDdKNUtiQ1NOV1NwUmNMaW92L2I4ST0KNno2clpnWTVxemtPbGMxL1pPZ2pRV1NZbVdhdGgyT1BnQng5L1J6RHVxbz0KelNSRmNobDNvTS9QU0J1WUVuWmdrd3o2SG5HVjdiQytEUkZlMDBudUJGaz0KcHRuL2xoeTFlcTNpeHpEanBHVVMxSjVZVDFrVEtlMW9tcUxpRGNPSTRlcz0KOXdwempHcE9mb3p0ZEFXcHhwWU52THpDbGgvVU5rYTVCNjRCV01GcEdVMD0KOUpHZE05Nzd4SjJJTkFIZ2dGSjBKczhvUDVKb0JIQ1dsRTEzSzFtSmQvdz0KR3Z2eWdiVEsvakIybHBVbE41Q250SjlGWUdOQmY0TG5Idzl0a2FxYWVUZz0K"
        }
      ],
      "metadata": [
        {
          "hint": "proposalmetadata",
          "digest": "cd7e75c3df810965c48c3c03a47062a1f5bf7e4458b036380877d3c59e331b41",
          "payload": "eyJuYW1lIjoiMjI1ZDJiZTFiYWQ2ZWU0MiJ9"
        }
      ],
      "publickey": "72a1a0f19d6d76b9bbec069f5672fa9f22485961b1dffe8c570558e88168076a",
      "signature": "981711bbf6cf408859f5eeab71bc5ec5a3fb4a723d3c853ede20415c9a5db1f2fd53265f73d79389e54b3ef5e0e924d0b48dee5b380c90ed093a3adcd7dab708"
    }
    {
      "timestamp": 1602104519,
      "censorshiprecord": {
        "token": "98daf0732ac3006c0000",
        "merkle": "928b9cede1846ba542a81d9a7968baff2b7f7cc4d80f52957746be8f6c3869de",
        "signature": "e30fc5332197f7b8f8fb8f73228a79295c7328d75aff10c123eb00d18e29fbd1a3fb96839f738c1ba19169246b018be389b8898afa1f4466b11a69c036187407"
      }
    }

Proposals are identified by their censorship record token in all other
commands. The censorship record token of the proposal example shown above is
`98daf0732ac3006c0000`.

## Make a proposal public (admin privileges required)

The proposal must first be vetted by an admin and have the proposal status set
to public before it will be publicly viewable.

    $ pictl proposalsetstatus [token] public

Now that the proposal status has been made public, any user can comment on the
proposal. Once the proposal author feels the discussion period was sufficient,
they can authorize the voting period to start.

## Authorize the voting period on a proposal (must be author)

Before an admin can start the voting period on a proposal the author must
authorize the vote.

    $ pictl voteauthorize [token]

## Start a proposal vote (admin privileges required)

Once a proposal vote has been authorized by the author, an admin can start the
voting period at any point.

    $ pictl votestart [token]

## Voting on a proposal

Voting on a proposal can be done using either `pictl` or `politeiavoter`.
`pictl` is for development uses only. `politeiavoter` should be used when
voting on production proposals.

### politeiavoter

See the [politeiavoter](https://github.com/decred/politeia/tree/master/politeiawww/cmd/politeiavoter/)
documentation for more information on using `politeiavoter`.

### pictl

You can vote on testnet proposals using `pictl` if you have the following
setup:
- dcrwallet is running locally on testnet and on the default port.
- A dcrwallet client cert has been setup for `pictl` using the instructions
  in the `Dcrwallet Authentication` section of this README. 

Cast a ballot of DCR ticket votes.

    $ pictl castballot [token] [voteID]

# Dcrwallet Authentication

Voting requires access to wallet GRPC. Therefore this tool needs the wallet's
server certificate to authenticate the server, as well as a local client
keypair to authenticate the client to `dcrwallet`.  The server certificate by
default will be found in `~/.dcrwallet/rpc.cert`, and this can be modified to
another path using the `--walletgrpccert` flag.  Client certs can be generated
using [`gencerts`](https://github.com/decred/dcrd/blob/master/cmd/gencerts/)
and `pictl` will read `client.pem` and `client-key.pem` from its
application directory by default.  The certificate (`client.pem`) must be
appended to `~/.dcrwallet/clients.pem` in order for `dcrwallet` to trust the
client.

For example:

```
$ gencerts ~/.pictl/client{,-key}.pem
$ cat ~/.pictl/client.pem >> ~/.dcrwallet/clients.pem
```

# Dev commands

`pictl` comes with commands that are useful during development. 

`seedproposals` seeds the backend with users, proposals, comments, and comment
upvotes/downvotes.

    $ pictl seedproposals email@example.com password

`votetestsetup` and `votetest` can be used to setup a batch of proposal votes
then to vote on them using your eligible tickets.

    $ pictl votetestsetup email@example.com password
    $ pictl votetest

Print the help message, `pictl -h`, to see a full list of these dev commands.
