#!/bin/bash
#
# Use politeiawwwcli to test the politeiawww API routes

readonly PROP_STATUS_NOT_REVIEWED=2
readonly PROP_STATUS_CENSORED=3
readonly PROP_STATUS_PUBLIC=4

cmd="politeiawwwcli -j"
admin_email=""
admin_password=""
override_token=""
print_json="false"
vote="false"

# expect_success executes the passed in command and ensures that the command
# exits with no errors. expect_success is used when you expect a command to
# succeed and you don't need to store the output.
expect_success() {
  if [ "$print_json" == "true" ]; then
    # execute passed in command. stdout will be printed to the console.
    $1
  else
    # execute passed in command and suppress stdout
    $1 > /dev/null
  fi

  # check exit status for errors. Exit script if errors found.
  if [ $? -ne 0 ]; then
    exit 1
  fi
}

# expect_failure executes the passed in command and ensures that the command
# exits with an error. expect_failure is used when you expect a command to fail
# and you don't need to store the output.
expect_failure() {
  if [ "$print_json" == "true" ]; then
    # execute passed in command. stdout will be printed to the console.
    $1
  else
    # execute passed in command and suppress stdout and stderr
    $1 &> /dev/null
  fi

  # check exit status for errors.  Exit script if no errors found.
  if [ $? -eq 0 ]; then
    echo "Expected failure, but did not recieve any errors."
    exit 1
  fi
}

# check_error checks the exit status of the previously run command and exits 
# the script if an error is found. This allows you to save the output of a
# command to a variable, then call check_error to check the exit status of the
# command. The variable containing the command's output is passed to 
# check_error and is written to stdout if the json flag is present.
check_error() {
  # check exit status of previous command
  if [ $? -ne 0 ]; then
    if [ "$print_json" == "true" ]; then
      echo $1
    fi
    exit 1
  fi

 if [ "$print_json" == "true" ]; then
   echo $1
 fi
}

# error writes an error message to stderr and exits the script
error() {
  echo "Error: $@" >&2
  exit 1
}

# run_admin_routes tests the politeiawww api routes that require admin privileges
run_admin_routes() {
  echo "Admin - Login"
  login=`$cmd login $admin_email $admin_password`
  check_error "$login"
  
  # validate that the user is an admin
  is_admin=`echo $login | jq -r '. | select(.userid).isadmin'`
  if [ $is_admin != "true" ]; then
    error "$admin_email is not an admin"
  fi

  echo "Admin - Me"
  me=`$cmd me`
  check_error "$me"
  me_email=`echo $me | jq -r '.email'`
  me_is_admin=`echo $me | jq -r '.isadmin'`

  if [ $me_email != $admin_email ]; then
    error "/me email got $me_email wanted $admin_email"
  fi 
  if [ $me_is_admin != "true" ]; then
    error "/me isAdmin got $me_is_admin wanted true"
  fi

  echo "Admin - Create new identity"
  expect_success "$cmd updateuserkey"

  echo "Admin - Unvetted paging"
  # only fetch proposals that were created during the execution of this script
  unvetted_page1=`$cmd getunvetted --after=$prop1_censorship_token`
  check_error "$unvetted_page1"
  page1_last_censorship_token=`echo $unvetted_page1 | jq -r ".[] | last | .censorshiprecord.token"` 

  unvetted_page2=`$cmd getunvetted --after=$page1_last_censorship_token` 
  check_error "$unvetted_page2" 
  unvetted_page2_length=`echo $unvetted_page2 | jq ".proposals | length"` 

  if [ $unvetted_page2_length -eq 0 ]; then
    error "Empty 2nd page of unvetted proposals"
  fi

  echo "Admin - Get proposal"
  pr1=`$cmd getproposal $prop1_censorship_token` 
  check_error "$pr1"
  pr1_files_length=`echo $pr1 | jq ".proposal.files | length"`

  if [ $pr1_files_length -eq 0 ]; then
    error "pr1 expected proposal data"
  fi

  echo "Admin - Set proposal status: move prop1 to public"
  psr1=`$cmd setproposalstatus $prop1_censorship_token $PROP_STATUS_PUBLIC`
  check_error "$psr1"
  prop1_status=`echo $psr1 | jq -r ". | select(.proposal).proposal.status"`

  if [ $prop1_status != $PROP_STATUS_PUBLIC ]; then
    error "Invalid status got $prop1_status wanted $PROP_STATUS_PUBLIC"
  fi
  
  echo "Admin - Set proposal status: move prop2 to censored"
  psr2=`$cmd setproposalstatus $prop2_censorship_token $PROP_STATUS_CENSORED`
  check_error "$psr2"
  prop2_status=`echo $psr2 | jq -r ". | select(.proposal).proposal.status"`

  if [ $prop2_status != $PROP_STATUS_CENSORED ]; then
    error "Invalid status got $prop2_status wanted $PROP_STATUS_CENSORED"
  fi

  echo "Admin - Get proposal: validate prop1 and prop2"
  _pr1=`$cmd getproposal $prop1_censorship_token` 
  check_error "$_pr1"
  _pr1_censorship_token=`echo $_pr1 | jq -r ".proposal.censorshiprecord.token"`
  _pr1_status=`echo $_pr1 | jq -r ".proposal.status"`

  if [ $_pr1_censorship_token != $prop1_censorship_token ]; then
    error "_pr1 invalid got $_pr1_censorship_token wanted $prop1_censorship_token"
  fi

  if [ $_pr1_status != $PROP_STATUS_PUBLIC ]; then
    error "_pr1 invalid status got $_pr1_status wanted $PROP_STATUS_PUBLIC"
  fi

  _pr2=`$cmd getproposal $prop2_censorship_token` 
  check_error "$_pr2"
  _pr2_censorship_token=`echo $_pr2 | jq -r ".proposal.censorshiprecord.token"`
  _pr2_status=`echo $_pr2 | jq -r ".proposal.status"`

  if [ $_pr2_censorship_token != $prop2_censorship_token ]; then
    error "_pr2 invalid got $_pr2_censorship_token wanted $prop2_censorship_token"
  fi

  if [ $_pr2_status != $PROP_STATUS_CENSORED ]; then
    error "_pr2 invalid status got $_pr2_status wanted $PROP_STATUS_CENSORED"
  fi
  
  echo "Admin - New comment 1: prop1 no parent"
  cr1=`$cmd newcomment $prop1_censorship_token "parentComment"`
  check_error "$cr1"
  cr1_comment_id=`echo $cr1 | jq -r ". | select(.commentid).commentid"`

  echo "Admin - New comment 1: prop1 with parent"
  expect_success "$cmd newcomment $prop1_censorship_token childComment $cr1_comment_id"

  echo "Admin - New comment 1: prop1 with parent"
  expect_success "$cmd newcomment $prop1_censorship_token childComment $cr1_comment_id"

  echo "Admin - New comment 2: prop1 no parent"
  cr2=`$cmd newcomment $prop1_censorship_token "parentComment"`
  check_error "$cr2"
  cr2_comment_id=`echo $cr2 | jq -r ". | select(.commentid).commentid"`

  echo "Admin - New comment 2: prop1 with parent"
  expect_success "$cmd newcomment $prop1_censorship_token childComment $cr2_comment_id"

  echo "Admin - New comment 2: prop1 with parent"
  expect_success "$cmd newcomment $prop1_censorship_token childComment $cr2_comment_id"

  echo "Admin - Get comments: validate number of comments on prop1"
  gcr1=`$cmd getcomments $prop1_censorship_token`
  check_error "gcr1"
  gcr1_num_comments=`echo $gcr1 | jq ".comments | length"`

  if [ $gcr1_num_comments -ne 6 ]; then
    error "Expected 6 comments, got $gcr1_num_comments"
  fi

  echo "Admin - Get proposal: validate number of comments on prop1"
  _pr1=`$cmd getproposal $prop1_censorship_token`
  check_error "$_pr1"
  _pr1_num_comments=`echo $_pr1 | jq ".proposal.numcomments"`

  if [ $_pr1_num_comments -ne 6 ]; then
    error "Expected 6 comments, got $_pr1_num_comments"
  fi

  echo "Admin - Get comments: validate number of comments on prop2"
  gcr2=`$cmd getcomments $prop2_censorship_token`
  check_error "gcr2"
  gcr2_num_comments=`echo $gcr2 | jq ".comments | length"`

  if [ $gcr2_num_comments -ne 0 ]; then
    error "Expected 0 comments, got $gcr2_num_comments"
  fi

  echo "Admin - Get proposal: validate number of comments on prop2"
  _pr2=`$cmd getproposal $prop2_censorship_token`
  check_error "$_pr2"
  _pr2_num_comments=`echo $_pr2 | jq ".proposal.numcomments"`

  if [ $_pr2_num_comments -ne 0 ]; then
    error "Expected 0 comments, got $_pr2_num_comments"
  fi
}

# run_vote_routes tests the politeiawww api routes that handle proposal voting
run_vote_routes() {
  echo "Vote - Login"
  login=`$cmd login $admin_email $admin_password`
  check_error "$login"

  echo "Vote - Verify admin status"
  is_admin=`echo $login | jq -r ". | select(.userid).isadmin"`
  if [ $is_admin != "true" ]; then
    error "$admin_email is not an admin"
  fi

  echo "Vote - Update user identity"
  expect_success "$cmd updateuserkey"

  echo "Vote - New proposal"
  vprop=`$cmd newproposal --random`
  check_error "$vprop"
  vprop_censorship_token=`echo $vprop | jq -r '. | select(.censorshiprecord).censorshiprecord.token'`

  echo "Vote - Start vote failure: wrong state"
  expect_failure "$cmd startvote $vprop_censorship_token"
    
  echo "Vote - Move proposal to vetted"
  psr=`$cmd setproposalstatus $vprop_censorship_token $PROP_STATUS_PUBLIC`
  check_error "$psr"
  vprop_status=`echo $psr | jq -r ". | select(.proposal).proposal.status"`

  if [ $vprop_status != $PROP_STATUS_PUBLIC ]; then
    error "Invalid status got $vprop_status wanted $PROP_STATUS_PUBLIC"
  fi

  echo "Vote - Add comment"
  expect_success "$cmd newcomment $vprop_censorship_token parentComment"

  echo "Vote - Start vote"
  expect_success "$cmd startvote $vprop_censorship_token"
}

print_usage() { 
  echo "Usage:
  politeaiwww_refclient.sh [options] [ -e admin_email ] [ -p admin_password ]

Options:
  -e    specify an admin email
  -h    show this help message
  -j    print json output
  -o    override token for faucet
  -p    specify an admin password
  -s    specify server (i.e. host)
  -v    run vote routes

* to run admin routes, specify admin login credentials using -e and -p"
}

main() {
  # Parse command line flags
  while getopts 'e:hjo:p:s:v' flag; do
    case "${flag}" in
      e) admin_email="${OPTARG}" ;;
      h) print_usage
         exit 0 ;;
      j) print_json="true" ;;
      o) override_token="${OPTARG}" ;;
      p) admin_password="${OPTARG}" ;;
      s) cmd="politeiawwwcli -j --host=${OPTARG}" ;;
      v) vote="true" ;;
      *) print_usage
         exit 1 ;;
    esac
  done

  # Start tests
  echo "Version: fetch CSRF token"
  expect_success "$cmd version"

  # Run vote routes if -v flag is used
  if [ $vote == "true" ]; then
    if [[ $admin_email == "" || $admin_password == "" ]]; then
      error "Vote routes require admin credentials"
    fi

    run_vote_routes
    printf "\nCompleted with no errors\n"
    exit 0
  fi

  echo "Policy"
  policy=`$cmd policy`
  check_error "$policy"
  min_password_length=`echo $policy | jq ".minpasswordlength"`

  echo "Generate user credentials"
  username1=`openssl rand -hex $min_password_length`
  email1="$username1@example.com"
  password1="$username1"

  username2=`openssl rand -hex $min_password_length`
  password2="$username2"

  printf "  Username: %s\n  Email: %s\n  Password: %s\n" $username1 $email1 $password1

  echo "Create new user & verify"
  newuser=`$cmd newuser $email1 $username1 $password1 --save --verify`
  check_error "$newuser"
  paywall_address=`echo $newuser | jq -r '.| select(.paywalladdress).paywalladdress'`
  paywall_amount=`echo $newuser | jq '. | select(.paywallamount).paywallamount'`

  # Paywall fee
  if [[ $paywall_address != "" && $paywall_amount -ne 0 ]]; then
    printf "Paywall\n  Address: %s\n  Amount: %s\n  Sending DCR...\n" $paywall_address $paywall_amount
    faucet=`$cmd faucet $paywall_address $paywall_amount --overridetoken=$override_token`
    check_error "$faucet"
    faucet_tx=`echo $faucet | jq -r ".faucetTx"`
    echo "  faucet_tx: $faucet_tx"
  fi

  echo "New proposal failure: user hasn't paid paywall"
  expect_failure "$cmd newproposal --random"

  echo "Reset password"
  expect_success "$cmd resetpassword $email1 $password2"

  echo "Login failure: incorrect password"
  expect_failure "$cmd login $email1 $password1"

  echo "Login"
  login=`$cmd login $email1 $password2`
  check_error "$login"

  echo "Admin failure"
  me=`$cmd me`
  check_error "$me"
  is_admin=`echo $me | jq '.isadmin'`
  if [ "$is_admin" != "false" ]; then
    error "Expected non-admin"
  fi

  echo "Secret"
  expect_success "$cmd secret"

  echo "Me"
  expect_success "$cmd me"

  echo "Change password"
  expect_success "$cmd changepassword $password2 $password1"

  echo "Change username"
  expect_success "$cmd changeusername $password1 $username2"

  # Wait for paywall payment to get confirmed
  echo "Verify user payment"
  has_paid="false"
  verifyuserpayment=`$cmd verifyuserpayment $faucet_tx`
  check_error "$verifyuserpayment"
  has_paid=`echo $verifyuserpayment | jq '.haspaid'`
  while [ "$has_paid" == "false" ]; do
    echo "Waiting for confirmations..."
    sleep 15
    verifyuserpayment=`$cmd verifyuserpayment $faucet_tx`
    check_error "$verifyuserpayment"
    has_paid=`echo $verifyuserpayment | jq '.haspaid'`
  done 

  echo "New proposal #1"
  prop1=`$cmd newproposal --random`
  check_error "$prop1"
  prop1_censorship_token=`echo $prop1 | jq -r '. | select(.censorshiprecord).censorshiprecord.token'`

  # Get proposals for user and validate that it matches prop1
  echo "Proposals for user"
  me=`$cmd me`
  check_error "$me"
  userId=`echo $me | jq -r ".userid"`

  userproposals=`$cmd userproposals $userId`
  check_error "$userproposals"
  user_props=`echo $userproposals | jq '.proposals'`
  user_prop1_censorship_token=`echo $user_props | jq -r ".[0].censorshiprecord.token"`

  if [  `echo $user_props | jq '. | length'` -ne 1 ]; then
    error "Incorrect number of proposals returned for user"
  fi

  if [ $user_prop1_censorship_token != $prop1_censorship_token ]; then
    error "Proposal tokens don't match"
  fi

  echo "Create new identity"
  expect_success "$cmd updateuserkey"

  echo "New proposal #2"
  prop2=`$cmd newproposal --random`
  check_error "$prop2"
  prop2_censorship_token=`echo $prop2 | jq -r '. | select(.censorshiprecord).censorshiprecord.token'`

  echo "Get proposal #1 and validate"
  pr1=`$cmd getproposal $prop1_censorship_token`
  check_error "$pr1"
  pr1_censorship_token=`echo $pr1 | jq -r '.proposal.censorshiprecord.token'`
  pr1_status=`echo $pr1 | jq -r '.proposal.status'`
  pr1_num_files=`echo $pr1 | jq '.proposal.files | length'`

  if [ $pr1_censorship_token != $prop1_censorship_token ]; then
    error "Proposal tokens don't match"
  fi

  if [ $pr1_status -ne $PROP_STATUS_NOT_REVIEWED ]; then
    error "pr1 invalid status got $pr1_status wanted $PROP_STATUS_NOT_REVIEWED"
  fi

  if [ $pr1_num_files -gt 0 ]; then
    error "pr1 unexpected proposal data recieved"
  fi

  echo "Get proposal #2 and validate"
  pr2=`$cmd getproposal $prop2_censorship_token`
  check_error "$pr2"
  pr2_censorship_token=`echo $pr2 | jq -r '.proposal.censorshiprecord.token'`
  pr2_status=`echo $pr2 | jq -r '.proposal.status'`
  pr2_num_files=`echo $pr2 | jq '.proposal.files | length'`

  if [ $pr2_censorship_token != $prop2_censorship_token ]; then
    error "Proposal tokens don't match"
  fi

  if [ $pr2_status -ne $PROP_STATUS_NOT_REVIEWED ]; then
    error "pr2 invalid status got $pr2_status wanted $PROP_STATUS_NOT_REVIEWED"
  fi

  if [ $pr2_num_files -gt 0 ]; then
    error "pr2 unexpected proposal data recieved"
  fi

  echo "Create 2 pages of proposals"
  prop_list_page_size=`echo $policy | jq ".proposallistpagesize"`
  for i in `seq 1 $prop_list_page_size`; do
    echo "  New proposal"
    expect_success "$cmd newproposal --random"
  done    

  echo "Get unvetted failure: only accessible by admin users"
  expect_failure "$cmd getunvetted"

  echo "Get vetted proposals"
  expect_success "$cmd getvetted"

  echo "Logout"
  expect_success "$cmd logout"

  echo "Secret failure: user not logged in"
  expect_failure "$cmd secret"

  echo "Me failure: user not logged in"
  expect_failure "$cmd me"

  if [[ $admin_email != "" && $admin_password != "" ]]; then
    run_admin_routes
  fi

  printf "\nCompleted with no errors\n"
}

main "$@"
