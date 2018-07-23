# politeiawwwcli

`politeiawwwcli` is a command line tool that allows you to interact with the Politeia API.

## Available Commands
```
activevotes        Retrieve all proposals being actively voted on
castvotes          Cast ticket votes for a specific proposal
changepassword     change the password for the currently logged in user
changeusername     change the username for the currently logged in user
commentsvotes      fetch all the comments voted by the user on a proposal
faucet             use the Decred testnet faucet to send DCR to an address
getcomments        fetch a proposal's comments
getproposal        fetch a proposal
getunvetted        fetch unvetted proposals
getvetted          fetch vetted proposals
login              login to Politeia
logout             logout of Politeia
me                 return the user information of the currently logged in user
newcomment         comment on a proposal
newproposal        submit a new proposal to Politeia
newuser            create a new Politeia user
policy             fetch server policy
proposalvotes      fetch vote results for a specific proposal
resetpassword      change the password for a user that is not currently logged in
secret
setproposalstatus  (admin only) set the status of a proposal
startvote          (admin only) start the voting period on a proposal
usernamesbyid      fetch usernames by their user ids
userproposals      fetch all proposals submitted by a specific user
verifyuser         verify user's email address
verifyuserpayment  check if the user has paid their user registration fee
version            fetch server info and CSRF token
votecomment        vote on a comment
```

## Application Options
```
    --host=    politeiawww host (default: https://proposals.decred.org)
-j, --json     Print JSON
-v, --verbose  Print request and response details

```

**If you're running Politeia locally, you need to make sure to specify the host.**  
`$ politeiawwwcli --host https://localhost:4443 <command>`

## Help Options
`-h, --help  Show the help message`

View a list of all commands
`$ politeiawwwcli -h`

View information about a specific command
`$ politeiawwwcli <command> -h`

## Persisting Data Between Commands
`politeiawwwcli` stores  user identity data (user's public/private key pair), session cookies, and CSRF tokens in the `AppData/Politeiawww/cli/` directory.  This allows you to login with a user and remain logged in between commands.  The user identity data and cookies are segmented by host, allowing you to login and interact with multiple hosts simultaneously.

## Usage

Create a new user.
```
$ politeiawwwcli -j --host https://localhost:4443 newuser email@example.com username password --verify --paywall
```
`--verify` will satisfy the email verification requirement for the user.  
`--paywall` will use the Decred testnet faucet to satisfy the user registration fee requirement.  

**Note: If you use the --paywall flag, you will still need to wait for block confirmations before you'll be allowed to submit proposals.**

Login with the user.  
`$ politeiawwwcli --host https://localhost:4443 login email@example.com password`

Once logged in, you can submit proposals, comment on proposals, cast votes, or perform any of the other user actions that Politeia allows.  

## 403 Error
If you receive a 403 from the Politeia server, it's most likely an issue with the CSRF tokens.  You can fix this by running either the `version` command or by loggin in with a user.

## Proposal Status Codes
If your user has admin privileges, they can set the status of a proposal with the `setproposalstatus` command.  The proposal status codes are listed below.  

```
PropStatusInvalid     PropStatusT = 0 // Invalid status
PropStatusNotFound    PropStatusT = 1 // Proposal not found
PropStatusNotReviewed PropStatusT = 2 // Proposal has not been reviewed
PropStatusCensored    PropStatusT = 3 // Proposal has been censored
PropStatusPublic      PropStatusT = 4 // Proposal is publicly visible
PropStatusLocked      PropStatusT = 6 // Proposal is locked
```
