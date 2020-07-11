#!/usr/bin/env bash
# This script sets up the CockroachDB databases for the politeiawww user data
# and assigns user privileges.
# This script requires that you have already created CockroachDB certificates
# using the cockroachcerts.sh script and that you have a CockroachDB instance
# listening on the default port localhost:26257.

set -ex

# COCKROACHDB_DIR must be the same directory that was used with the
# cockroachcerts.sh script.
COCKROACHDB_DIR=$1
if [ "${COCKROACHDB_DIR}" == "" ]; then
  COCKROACHDB_DIR="${HOME}/.cockroachdb"
fi

# ROOT_CERTS_DIR must contain client.root.crt, client.root.key, and ca.crt.
readonly ROOT_CERTS_DIR="${COCKROACHDB_DIR}/certs/clients/root"

if [ ! -f "${ROOT_CERTS_DIR}/client.root.crt" ]; then
  >&2 echo "error: file not found ${ROOT_CERTS_DIR}/client.root.crt"
  exit
elif [ ! -f "${ROOT_CERTS_DIR}/client.root.key" ]; then
  >&2 echo "error: file not found ${ROOT_CERTS_DIR}/client.root.key"
  exit
elif [ ! -f "${ROOT_CERTS_DIR}/ca.crt" ]; then
  >&2 echo "error: file not found ${ROOT_CERTS_DIR}/ca.crt"
  exit
fi

# Database names
readonly DB_MAINNET="users_mainnet"
readonly DB_TESTNET="users_testnet3"

# Database usernames
readonly USER_POLITEIAWWW="politeiawww"

# Create the mainnet and testnet databases for the politeiawww user data.
cockroach sql \
  --certs-dir="${ROOT_CERTS_DIR}" \
  --execute "CREATE DATABASE IF NOT EXISTS ${DB_MAINNET}"

cockroach sql \
  --certs-dir="${ROOT_CERTS_DIR}" \
  --execute "CREATE DATABASE IF NOT EXISTS ${DB_TESTNET}"

# Create politeiawww user and assign privileges.
cockroach sql \
  --certs-dir="${ROOT_CERTS_DIR}" \
  --execute "CREATE USER IF NOT EXISTS ${USER_POLITEIAWWW}"

cockroach sql \
  --certs-dir="${ROOT_CERTS_DIR}" \
  --execute "GRANT CREATE, SELECT, DROP, INSERT, DELETE, UPDATE \
  ON DATABASE ${DB_MAINNET} TO  ${USER_POLITEIAWWW}"

cockroach sql \
  --certs-dir="${ROOT_CERTS_DIR}" \
  --execute "GRANT CREATE, SELECT, DROP, INSERT, DELETE, UPDATE \
  ON DATABASE ${DB_TESTNET} TO  ${USER_POLITEIAWWW}"
