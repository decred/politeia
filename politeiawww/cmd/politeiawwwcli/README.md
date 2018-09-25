# politeiawwwcli

politeiawwwcli is a command line tool that allows you to interact with the
politeiawww API.

## Available Commands
You can view the available commands and application options by using the help
flag.

`$ politeiawwwcli -h`

You can view details about a specific command, including required arguments,
by putting the help flag after the command.

`$ politeiawwwcli <command> -h`

## Persisting Data Between Commands
politeiawwwcli stores  user identity data (the user's public/private key
pair), session cookies, and CSRF tokens in the `AppData/Politeiawww/cli/`
directory.  This allows you to login with a user and use the same session data
for subsequent commands.  The data is segmented by host, allowing you to login
and interact with multiple hosts simultaneously.

The location of the `AppData` directory varies based on your operating system.

**macOS**

```
/Users/<username>/Library/Application Support/Politeiawwww/cli/
```

**Windows**

```
C:\Users\<username>\AppData\Local\Politeiawww/cli/
```

**Ubuntu**

```
~/.politeiawww/cli/
```

## Setup Configuration File
politeiawwwcli has a configuration file that you can setup to make execution
easier.  You should create the configuration file under the following paths.

**macOS**

```
/Users/<username>/Library/Application Support/Politeiawww/cli/politeiawwwcli.conf
```

**Windows**

```
C:\Users\<username>\AppData\Local\Politeiawww/cli/politeiawwwcli.conf
```

**Ubuntu**

```
~/.politeiawww/cli/politeiawwwcli.conf
```

If you're developing locally, you'll want to set the politeiawww host in the
configuration file since the default politeiawww host is
`https://proposals.decred.org`.  Copy this line into your `politeiawwwcli.conf`
file.

```
host=https://127.0.0.1:4443
```

## Usage

### Create a new user
```
$ politeiawwwcli newuser email@example.com username password --verify --paywall
```

`--verify` and `--paywall` are options that can be used when running
politeiawww on testnet to make the user registration process a little simplier.

`--verify` will satisfy the email verification requirement for the user.

`--paywall` will use the Decred testnet faucet to satisfy the user registration
fee requirement. 

**If you use the `--paywall` flag, you will still need to wait for block
confirmations before you'll be allowed to submit proposals.**

### Login with the user
```
$ politeiawwwcli login email@example.com password
```

## Give your user admin privileges and add proposal credits to their account

Proposal credits are required in order to submit a proposal. They are a spam
prevention measure that would normally need to be purchased using DCR, but if
you're running politeiawww locally, you can use the politeiawww_dbutil tool 
to add proposal credits to your account.  You'll also need to give your user 
admin privileges if you want to be able to start proposal votes.

**You need to stop politeiawww in order to run these commands.  You'll
get a `resource temporarily unavailable` error if you don't.**

```
$ politeiawww_dbutil -testnet -setadmin email@example.com true
$ politeiawww_dbutil -testnet -addcredits email@example.com 50
```

**Start politeiawww back up.**

### Submit a new proposal

When submitting a proposal, you can either specify a markdown file or you can
use the `--random` flag to have politeiawwwcli generate a random proposal for
you.

```
$ politeiawwwcli newproposal --random
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
    "token": "299d6defa32b77f0a5534168256c6712a02c0de8037747ac213f650065529043",
    "merkle": "362ca2a93194ebee058640f36b0ba74955760cd495f2626d740334de2cbb2a8d",
    "signature": "729269ef6bb45003a4728c40ff5c7f1ecbc44bfcff459d43274155e42e971a0ef8830e692eb833b049df5460edd850c77f21353fe24fd43a454388b7b89d7e00"
  }
}
```

The proposal must first be vetted by an admin before it is publicily viewable. 
Proposals are identified by their censorship record token, which can be found
in the output of the `newproposal` command.

### Make a proposal public (admin privileges required)
```
$ politeiawwwcli setproposalstatus [censorshipRecordToken] 4
```

Now that the proposal has been vetted and is publicly available, you can
comment on the proposal or an admin can start the voting period for the
proposal.

### Start a proposal vote (admin privileges required)
```
$ politeiawwwcli startvote [censorhipRecordToken]
```

### Voting on a proposal - politeiavoter
Voting on a proposal can be done using the 
[politeiavoter](https://github.com/decred/politeia/tree/master/politeiavoter/)
tool.

### Voting on a proposal - politeiawwwcli
You can also vote on proposals using `politeiawwwcli`, but for right now, it 
only works on testnet and you have to be running your dcrwallet locally using
the default port.  If you are doing these things, then you can use the 
`inventory`, `vote`, and `tally` commands.

`inventory` will fetch all of the active proposal votes and print the details
for the proposal votes in which you have eligible tickets.

```
$ politeiawwwcli inventory
Token: ee42e2e231c02b3d202de9f5df7b2d361a5ab078f675a8823e3db73afb799899
  Proposal        : This is the proposal title
  Eligible tickets: 3
  Start block     : 30938
  End block       : 32954
  Mask            : 3
  Vote Option:
    ID                   : no
    Description          : Don't approve proposal
    Bits                 : 1
  Vote Option:
    ID                   : yes
    Description          : Approve proposal
    Bits                 : 2
    To choose this option: politeiawwwcli vote ee42e2e231c02b3d202de9f5df7b2d361a5ab078f675a8823e3db73afb799899 yes
```

`vote` will cast votes using your eligible tickets.  You'll be asked to enter
your wallet password.

```
$ politeiawwwcli vote ee42e2e231c02b3d202de9f5df7b2d361a5ab078f675a8823e3db73afb799899 yes
Enter the private passphrase of your wallet:
Votes succeeded: 3
Votes failed   : 0
```

`tally` will return the current voting resuts the for passed in proposal.

```
$ politeiawwwcli tally ee42e2e231c02b3d202de9f5df7b2d361a5ab078f675a8823e3db73afb799899
Vote Option:
  ID                   : no
  Description          : Don't approve proposal
  Bits                 : 1
  Votes received       : 0
  Percentage           : 0%
Vote Option:
  ID                   : yes
  Description          : Approve proposal
  Bits                 : 2
  Votes received       : 3
  Percentage           : 100%
```

## Proposal Status Codes
A proposal record will include a numeric staus code to represent the status of
the proposal.  These status codes are listed below.

```
PropStatusInvalid      0 // Invalid status
PropStatusNotFound     1 // Proposal not found
PropStatusNotReviewed  2 // Proposal has not been reviewed
PropStatusCensored     3 // Proposal has been censored
PropStatusPublic       4 // Proposal is publicly visible
PropStatusLocked       6 // Proposal is locked
```
