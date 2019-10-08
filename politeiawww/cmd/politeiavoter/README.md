# Politeia Voter

`politeiavoter` is a command line utility that can be used to issue votes on
proposals.

Configuration and logs Linux/BSD/POSIX:
The tool keeps logs and configuration files in the ~/.politeiavoter directory

Configuration and logs Windows:
The tool keeps logs and configuration files in the %LOCALAPPDATA%\Politeiavoter
directory

Configuration and logs macOS/OSX:
The tool keeps logs and configuration files in the ~/Library/Application
Support/Politeiavoter directory

In the following examples the config file contained the following entry:
```
testnet=1
```

## Requirements

Voting requires access to wallet GRPC. Therefore this tool needs the wallet
certificate. By default the tool will look in `~/.dcrwallet/rpc.cert`.

In order to sign votes ```politeiavoter``` requires the wallet passphrase.

In order to use the "vote trickler" functionality one must use Tor. Without Tor
the server administrator will still know where the votes came from rendering
the trickling worthless.

## Workflow

```politeiavoter``` supports three commands:

```
  inventory          - Retrieve all proposals that are being voted on
  vote               - Vote on a proposal
  tally              - Tally votes on a proposal
```

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
The tool will prompt for the wallet decryption passphrase and then takes a few
seconds to vote.

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

```politeiavoter``` has three settings to control this behavior. First there is
the ```--proxy``` setting to make ```politeiavoter``` use a Tor proxy. This
setting is *REQUIRED* since it makes no sense to trickle votes from the same
IP.  The second setting is ```--trickle```. Tha setting must be set to enable
trickling.

The third setting is ```--voteduration``` that sets the maximum duration to
trickle out votes. Valid modifiers are h for hours, m for minutes and s for
seconds (e.g. 3h18m15s). If this setting is NOT set than ```politeiavoter```
will try to smear it out over the remaining vote duration minus one day. If it
can't autodetect a proper duration it will error out so that the user can
provide one.

E.g. running Tor software on the local machine with 10 votes:
```
politeiavoter --proxy=127.0.0.1:9050 --trickle --voteduration=30m vote 8bdebbc55ae74066cc57c76bc574fd1517111e56b3d1295bde5ba3b0bd7c3f67 yes
```

Running Tor software on the local machine with 10 votes and autodetect duration:
```
politeiavoter --proxy=127.0.0.1:9050 --trickle vote 8bdebbc55ae74066cc57c76bc574fd1517111e56b3d1295bde5ba3b0bd7c3f67 yes
```
