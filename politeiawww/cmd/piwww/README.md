piwww
====

piwww is a command line tool that allows you to interact with the politeiawww
pi API.

# Available Commands
You can view the available commands and application options by using the help
flag.

    $ piwww -h 

You can view details about a specific command by using the help command.

    $ piwww help <command>

# Persisting Data Between Commands
piwww stores  user identity data (the user's public/private key pair), session
cookies, and CSRF tokens in the piwww directory.  This allows you to login with
a user and use the same session data for subsequent commands.  The data is
segmented by host, allowing you to login and interact with multiple hosts
simultaneously.

The location of the piwww directory varies based on your operating system.

**macOS**

`/Users/<username>/Library/Application Support/Piwww`

**Windows**

`C:\Users\<username>\AppData\Local\Piwww`

**Ubuntu**

`~/.piwww`

# Setup Configuration File
piwww has a configuration file that you can setup to make execution easier.
You should create the configuration file under the following paths.

**macOS**

`/Users/<username>/Library/Application Support/Piwww/piwww.conf`

**Windows**

`C:\Users\<username>\AppData\Local\Piwww/piwww.conf`

**Ubuntu**

`~/.piwww/piwww.conf`

If you're developing locally, you'll want to set the politeiawww host in the
configuration file to your local politeiawww instance. The host defaults to
`https://proposals.decred.org`.  Copy these lines into your `piwww.conf` file.
`skipverify` is used to skip TLS certificate verification and should only be
used when running politeia locally.

```
host=https://127.0.0.1:4443
skipverify=true
```

# Example Usage

## Create a new user

    $ piwww usernew email@example.com username password --verify --paywall

`--verify` and `--paywall` are options that can be used when running
politeiawww on testnet to make the user registration process quicker.

`--verify` will satisfy the email verification requirement for the user.

`--paywall` will use the Decred testnet faucet to satisfy the user registration
fee requirement. 

**If you use the `--paywall` flag, you will still need to wait for block
confirmations before you'll be allowed to submit proposals.**

## Login with the user

    $ piwww login email@example.com password

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
use the `--random` flag to have piwww generate a random proposal for you.

    $ piwww proposalnew --random
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

    $ piwww proposalstatusset --unvetted [token] public

Now that the proposal status has been made public, any user can comment on the
proposal. Once the proposal author feels the discussion period was sufficient,
they can authorize the voting period to start.

## Authorize the voting period on a proposal (must be author)

Before an admin can start the voting period on a proposal the author must
authorize the vote.

    $ piwww voteauthorize [token]

## Start a proposal vote (admin privileges required)

Once a proposal vote has been authorized by the author, an admin can start the
voting period at any point.

    $ piwww votestart [token]

## Voting on a proposal

### politeiavoter

Voting on a proposal can be done using the `politeiavoter` tool.

[politeiavoter](https://github.com/decred/politeia/tree/master/politeiawww/cmd/politeiavoter/)

### piwww

You can also vote on proposals using the `piwww voteballot` command. This casts
a ballot of votes. This will only work on testnet and if you are running your
dcrwallet locally using the default port.

    $ piwww voteballot [token] [voteID]

# Reference implementation

The piwww `testrun` command runs a series of tests on all of the politeiawww pi
API routes.  This command can be used as a reference implementation for the pi
API.
