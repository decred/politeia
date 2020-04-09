#!/usr/bin/env bash

numUsers=$1
echo $numUsers
echo "Starting politeiad..."
tmux new-session -d -s politeiad 'politeiad'

# Wait a few seconds to ensure that politeiawww is ready for requests
echo "Waiting for politeiad to start..."
sleep 3

# Start politeiawww in basic piwww mode to create first user that will
# be the admin user
echo "Starting politeiawww..."
tmux new-session -d -s politeiawww 'politeiawww --mode=piwww'

# Wait a few seconds to ensure that politeiawww is ready for requests
echo "Waiting for politeiawww to start..."
sleep 3

# Create a new admin user
echo "Making a admin user: user/pass: admin/password"
newuser=`piwww newuser admin@decred.org admin password --verify`

# Set that admin user to admin in the db
politeiawww_dbutil -cockroachdb -testnet -setadmin admin true

# Kill politeiawww that is in piwww mode
echo "Stopping politeiawww..."
tmux kill-session -t politeiawww

# Restart politeiawww in cmsmode
echo "Starting politeiawww..."
tmux new-session -d -s politeiawww 'politeiawww --mode=cmswww'

# Wait a few seconds to ensure that politeiawww is ready for requests
echo "Waiting for politeiawww to start..."
sleep 3 

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