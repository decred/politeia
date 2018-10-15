# Politeia Voter

`politeiavoter` is a command line utility that can be used to issue votes on
proposals.

The tool keeps logs and configuration files, just like the other tools in the
Decred suite, in the ~/.politeiavoter directory (this varies for Windows and
OSX).

In the following examples the config file contained the following entry:
```
testnet=1
```

## Requirements

Voting requires access to wallet GRPC. Therefore this tool needs the wallet
certificate. By default the tool will look in `~/.dcrwallet/rpc.cert`.

Note: The tool will always prompt for the wallet password and is therefore
safe to run on the same machine as the wallet.

## Workflow

First one obtains the list of active proposals that are up for voting:
```
politeiavoter inventory
```

This will output all eligible votes.
```
Vote: 8bdebbc55ae74066cc57c76bc574fd1517111e56b3d1295bde5ba3b0bd7c3f67
  Proposal        : This is a description
  Start block     : 282899
  End block       : 284915
  Mask            : 3
  Eligible tickets: 9
  Vote Option:
    Id                   : no
    Description          : Don't approve proposal
    Bits                 : 1
    To choose this option: politeiavoter vote 8bdebbc55ae74066cc57c76bc574fd1517111e56b3d1295bde5ba3b0bd7c3f67 no
  Vote Option:
    Id                   : yes
    Description          : Approve proposal
    Bits                 : 2
    To choose this option: politeiavoter vote 8bdebbc55ae74066cc57c76bc574fd1517111e56b3d1295bde5ba3b0bd7c3f67 yes
```

In this example the user has **9** eligible tickets to vote.

The vote choice is printed during inventory and one can simply copy & paste
that into the shell.

```
politeiavoter vote 8bdebbc55ae74066cc57c76bc574fd1517111e56b3d1295bde5ba3b0bd7c3f67 yes
```
The tool will prompt for the wallet GRPC password and then takes a few seconds
to vote.

```
Enter the private passphrase of your wallet:
Votes succeeded: 9
Votes failed   : 0
```

Note: that the tool at this time votes the same choice for **all available**
tickets.

To get the current tally of votes.
```
politeiavoter tally 8bdebbc55ae74066cc57c76bc574fd1517111e56b3d1295bde5ba3b0bd7c3f67
Vote Option:
  Id                   : no
  Description          : Don't approve proposal
  Bits                 : 1
  Votes received       : 0
  Percentage           : 0%
Vote Option:
  Id                   : yes
  Description          : Approve proposal
  Bits                 : 2
  Votes received       : 9
  Percentage           : 100%
```

## Privacy considerations

By default, ```politeiavoter``` votes all eligible tickets in a single shot.
Thus giving away to the server operator which IP address controls which
tickets.  While this information is NOT visible externally the more privacy
conscience user may want to spread voting out over time and using tor to mask
IP address.

```politeiavoter``` has two settings to enable that behavior. First there is
the ```--proxy``` setting to make ```politeiavoter``` use a Tor proxy. The
second setting is ```--voteduration``` that sets the maximum duration to
trickle out votes. Valid modifiers are h for hours, m for minutes and s for
seconds (e.g. 3h18m15s). This value should be picked in the 2 to 5 minute per
vote range.

E.g. running Tor software on the local machine with 10 votes:
```
politeiavoter --proxy=127.0.0.1:9050 --voteduration=30m vote 8bdebbc55ae74066cc57c76bc574fd1517111e56b3d1295bde5ba3b0bd7c3f67 yes
```
