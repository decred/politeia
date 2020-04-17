#!/usr/bin/env bash

numUsers=$1
if [ -z "$1" ]
  then
    numUsers=0
fi

# Create a new admin user
echo "Making a admin user: user/pass: admin/password"
newuser=`politeiawww_dbutil -cockroachdb -testnet -addadmin admin@decred.org admin password`

# Login as the newly created admin user
echo "Login admin into politeiawww"
login=`cmswww login admin@decred.org password`

echo "Invite/register new users to cms"

counter=0
while [ "$counter" -le "$numUsers" ]
do
username="test$counter"
invite=`cmswww invite $username@decred.org false | jq ".verificationtoken"`
echo $invite
register=`cmswww register $username@decred.org --token=$invite --username=$username --password=password`

login=`cmswww login $username@decred.org password`
echo $username created successfully! email/user/pass: $username@decred.org/$username/password
login=`cmswww login admin@decred.org password`
((counter++))
done

# Kill politeiawww that is in cmswww mode
echo "Stopping politeiawww..."
tmux kill-session -t politeiawww

# Kill politeiad
echo "Stopping politeiad..."
tmux kill-session -t politeiad