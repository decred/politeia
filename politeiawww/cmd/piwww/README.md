# piwww

piwww is a command line tool that allows you to interact with the piwww API.

## Available Commands
You can view the available commands and application options by using the help
flag.

    $ piwww -h 

You can view details about a specific command by using the help command.

    $ piwww help <command>

## Persisting Data Between Commands
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

## Setup Configuration File
piwww has a configuration file that you can setup to make execution easier.
You should create the configuration file under the following paths.

**macOS**

`/Users/<username>/Library/Application Support/Piwww/piwww.conf`

**Windows**

`C:\Users\<username>\AppData\Local\Piwww/piwww.conf`

**Ubuntu**

`~/.piwww/piwww.conf`

If you're developing locally, you'll want to set the politeiawww host in the
configuration file since the default politeiawww host is
`https://proposals.decred.org`.  Copy these lines into your `piwww.conf` file.
`skipverify` is used to skip TLS certificate verification and should only be
used when running politeia locally.

```
host=https://127.0.0.1:4443
skipverify=true
```

## Usage

### Create a new user

    $ piwww usernew email@example.com username password --verify --paywall

`--verify` and `--paywall` are options that can be used when running
politeiawww on testnet to make the user registration process quicker.

`--verify` will satisfy the email verification requirement for the user.

`--paywall` will use the Decred testnet faucet to satisfy the user registration
fee requirement. 

**If you use the `--paywall` flag, you will still need to wait for block
confirmations before you'll be allowed to submit proposals.**

### Login with the user

    $ piwww login email@example.com password

### Assign admin privileges and create proposal credits

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

### Submit a new proposal

When submitting a proposal, you can either specify a markdown file or you can
use the `--random` flag to have piwww generate a random proposal for you.

    $ piwww proposalnew --random
    {
      "files": [
        {
          "name": "index.md",
          "mime": "text/plain; charset=utf-8",
          "digest": "362ca2a93194ebee058640f36b0ba74955760cd495f2626d740334de2cbb2a8d",
          "payload": "VGhpcyBpcyB0aGUgcHJvcG9zYWwgdGl0bGUKaFlOWll3NklzaE0rUVlWcU91aU45YThXdzdJUnRBYmVxSDV6dERTZkk0bz0KaXBTOUIwTmRNSHZEU3QrRkdHZFhoRHFMQ2RmQjF4eWFCTHJvTU01c1FnTT0KVXpHK2l3S0drZHhjaGRmdFMrYlpqZ0xsc1I4bGVmWDVnUCsxLy90ZXdJRT0KZWFvd1hNNkNGeVc4Z3dxRUVlc0J5aXNwbDNPSW9WemdyVlJZZ1ZEK1UzND0Kb3Q5WVlncGY0NGRFVlJ3ckdPb3FXQXJGaCtlUm1zemhZaGdnWEtkRTRhMD0KZWZXNmNwNTlCd05taS95b1Z0Zk5HU0dvWldrZzgvTUFFMllCMGZqcEREaz0KTUFicVVobW9WMFpIZ3NzNEpOMFBvU1F1V0pubWxNd3lrKzFIMUovSzVpQT0KWDlxQ3ZUcWZEbk1iTW1rV0V3bzNuSmtlL1dlaEN3dU1QMTdFYnczUi9HWT0KbUNPZ0ZpZEtGUmJKWTBnUCtrbGZUZUxUS3JSODBsSW92UGxVcjEvWjVjRT0KYWFzc04wWHZSZkdFM0ZIbHpXVFhTQlJ4ZVhCY2c5dmk1Wm5YUEhKWElUQT0K"
        }
      ],
      "publickey": "c2c2ea7f24733983bf8037c189f32b5da49e6396b7d21cb69efe09d290b3cb6d",
      "signature": "d4f38ee60e3032e67264732b13081ac36554fefd70079d40dcf7eb179e7cc4b2c80acc6460e9de1e816255bccfade659df6766c7371bd68592f010e3179feb0e"
    }
    {
      "censorshiprecord": {
        "token": "2c5d74209f37ca370000",
        "merkle": "362ca2a93194ebee058640f36b0ba74955760cd495f2626d740334de2cbb2a8d",
        "signature": "729269ef6bb45003a4728c40ff5c7f1ecbc44bfcff459d43274155e42e971a0ef8830e692eb833b049df5460edd850c77f21353fe24fd43a454388b7b89d7e00"
      }
    }

Proposals are identified by their censorship record token in all other
commands.

The proposal must first be vetted by an admin before it is publicily viewable. 
Proposals are identified by their censorship record token, which can be found
in the output of the `newproposal` command.

### Make a proposal public (admin privileges required)

    $ piwww proposalstatusset [token] public

Now that the proposal has been vetted and is publicly available, you can
comment on the proposal or authorize the voting period to start.

### Authorize the voting period on a proposal (must be author)

Before an admin can start the voting period on a proposal the author must
authorize the vote.

    $ piwww voteauthorize [token]

### Start a proposal vote (admin privileges required)

Once a proposal vote has been authorized by the author, an admin can start the
voting period.

    $ piwww votestart [token]

### Voting on a proposal - politeiavoter

Voting on a proposal can be done using the 
[politeiavoter](https://github.com/decred/politeia/tree/master/politeiavoter/)
tool.

### Voting on a proposal - piwww

You can also vote on proposals using the `piww` command `voteballot`. This
casts a ballot of votes.  This will only work on testnet and if you are running
your dcrwallet locally using the default port.

    $ piwww voteballot [token] [voteID]
