#!/usr/bin/env sh

numUsers=$1
if [ -z "$1" ]
  then
    numUsers=0
fi

ADMINEMAIL=$2
if [ -z "$2" ]
  then
    ADMINEMAIL="admin@decred.org"
fi

ADMINNAME=$3
if [ -z "$2" ]
  then
    ADMINNAME="admin"
fi

ADMINPASS=$4
if [ -z "$2" ]
  then
    ADMINPASS="password"
fi

# Create a new admin user
echo Making a admin user: user/pass: ${ADMINEMAIL}/${ADMINNAME}/${ADMINPASS}
newuser=`politeiawww_dbutil -cockroachdb -testnet -addadmin ${ADMINEMAIL} ${ADMINNAME} ${ADMINPASS}`

read -p "Restart politeiawww to confirm admin user and press enter to continue"

# Login as the newly created admin user
echo Login admin into politeiawww
login=`cmswww login admin@decred.org password`

echo Invite/register new users to cms

counter=0
while [ "$counter" -le "$numUsers" ]
do
username="test$counter"
invite=`cmswww invite $username@decred.org false | jq -r ".verificationtoken"`
register=cmswww register $username@decred.org $username password $invite

login=`cmswww login $username@decred.org password`
echo $username created successfully! email/user/pass: $username@decred.org/$username/password
login=`cmswww login admin@decred.org password`
((counter++))
done