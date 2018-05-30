# politeiawwwcli

`politeiawwwcli` is a command line tool that allows you to interact with the Politeia API.

## Available Commands
```
changepassword     change the password for the currently logged in user
changeusername     change the username for the currently logged in user
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
resetpassword      change the password for a user that is not currently logged in
secret
setproposalstatus  (admin only) set the status of a proposal
startvote          (admin only) start the voting period on a proposal
updateuserkey      update the user identity saved to appDataDir
userproposals      fetch all proposals submitted by a specific user
verifyuser         verify user's email address
verifyuserpayment  check if the user has paid their user registration fee
version            fetch version info and CSRF token 
```

## Application Options
```
     --host=     politeiawww host (default: https://127.0.0.1:4443)
 -j, --json      Print JSON
```

## Help Options
`-h, --help  Show the help message`

View a list of all commands
`$ politeiawwwcli -h`

View information about a specific command
`$ politeiawwwcli <command> -h`

## Persisting Data Between Commands
`politeiawwwcli` stores  user identity data (user's public/private key pair), session cookies, and CSRF tokens in the `AppData/Politeiawww/cli/` directory.  This allows you to login with a user and remain logged in between commands.  The user identity data and cookies are segmented by host, allowing you to login and interact with multiple hosts simultaneously.

## Usage

You need to first obtain a CSRF token from the Politeiawww server in order to interact with the API.  The `version` command fetches a CSRF token and saves it for future use.
```
$ politeiawwwcli version
```

Create a new user and save the user's identity for future use.
```
$ politeiawwwcli -j newuser email@example.com username somepassword --save --verify --paywall

--save      save the user's identity for future use
--verify    verify the user's email address
--paywall   use the testnet faucet to satisfy paywall requirement
--random    generate a random email address and password
```

You can now login with this user.  Session cookies are saved automatically.
`$ politeiawwwcli login email@example.com somepassword`

Once logged in, you can submit proposals or use any of the other commands that require you to be logged in or require a signature.
`$ politeiawwwcli newproposal`

If you decide to login with a different user, you can use the `updateuserkey` command to update the the user identity that is saved to `AppData/Politeiawww/cli`.
Note: This command uses the email as the private key so it should only be used for testing purposes.
```
$ politeiawwwcli login newUser@example.com somepassword
$ politeiawwwcli updateuserkey
```

## Proposal Status Codes
```
PropStatusInvalid     PropStatusT = 0 // Invalid status
PropStatusNotFound    PropStatusT = 1 // Proposal not found
PropStatusNotReviewed PropStatusT = 2 // Proposal has not been reviewed
PropStatusCensored    PropStatusT = 3 // Proposal has been censored
PropStatusPublic      PropStatusT = 4 // Proposal is publicly visible
PropStatusLocked      PropStatusT = 6 // Proposal is locked
```
