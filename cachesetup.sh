#!/usr/bin/env bash
# This script sets up the CockroachDB databases and users for the Politeia
# cache.  This script requires that you have already created all the necessary
# CockroachDB certificates using the cachecerts.sh script and that you have a
# CockroachDB instance listening on the default port localhost:26257.

set -ex

# CERTS_DIR must contain client.root.crt, client.root.key, and ca.crt for the
# CockroachDB instance.
readonly CERTS_DIR=$1

# Database names.
readonly DB_MAINNET="records_mainnet"
readonly DB_TESTNET="records_testnet3"

# Database user names.
readonly USER_POLITEIAD="records_politeiad"
readonly USER_POLITEIAWWW="records_politeiawww"

if [ "${CERTS_DIR}" == "" ]; then
    >&2 echo "Error: missing argument root user certs directory"
    exit
fi

# Create the mainnet and testnet databases for the politeiad records cache.
cockroach sql \
  --certs-dir="${CERTS_DIR}" \
  --execute "CREATE DATABASE IF NOT EXISTS ${DB_MAINNET}"

cockroach sql \
  --certs-dir="${CERTS_DIR}" \
  --execute "CREATE DATABASE IF NOT EXISTS ${DB_TESTNET}"

# Create the politeiad user and assign privileges.
cockroach sql \
  --certs-dir="${CERTS_DIR}" \
  --execute "CREATE USER IF NOT EXISTS ${USER_POLITEIAD}"

cockroach sql \
  --certs-dir="${CERTS_DIR}" \
  --execute "GRANT CREATE, SELECT, DROP, INSERT, DELETE, UPDATE \
  ON DATABASE ${DB_MAINNET} TO  ${USER_POLITEIAD}"

cockroach sql \
  --certs-dir="${CERTS_DIR}" \
  --execute "GRANT CREATE, SELECT, DROP, INSERT, DELETE, UPDATE \
  ON DATABASE ${DB_TESTNET} TO  ${USER_POLITEIAD}"

# Create politeiawww user and assign privileges.
cockroach sql \
  --certs-dir="${CERTS_DIR}" \
  --execute "CREATE USER IF NOT EXISTS ${USER_POLITEIAWWW}"

cockroach sql \
  --certs-dir="${CERTS_DIR}" \
  --execute "GRANT SELECT ON DATABASE ${DB_MAINNET} TO  ${USER_POLITEIAWWW}"

cockroach sql \
  --certs-dir="${CERTS_DIR}" \
  --execute "GRANT SELECT ON DATABASE ${DB_TESTNET} TO  ${USER_POLITEIAWWW}"
