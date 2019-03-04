#!/usr/bin/env bash
# This script sets up the CockroachDB databases and users for the cms database.
# This script requires that you have already created all the necessary
# CockroachDB certificates using the cmscerts.sh script and that you have a
# CockroachDB instance listening on the port localhost:26258.

set -ex

# CERTS_DIR must contain client.root.crt, client.root.key, and ca.crt for the
# CockroachDB instance.
readonly CERTS_DIR=$1

# Database names.
readonly DB_MAINNET="cms_mainnet"
readonly DB_TESTNET="cms_testnet3"

readonly HOST="localhost:26258"
# Database user names.
readonly 	USER_CMS="invoices_cmsdb" 

if [ "${CERTS_DIR}" == "" ]; then
    >&2 echo "Error: missing argument root user certs directory"
    exit
fi

# Create the mainnet and testnet databases for the cms database.
cockroach sql \
  --host="${HOST}" \
  --certs-dir="${CERTS_DIR}" \
  --execute "CREATE DATABASE IF NOT EXISTS ${DB_MAINNET}"

cockroach sql \
  --host="${HOST}" \
  --certs-dir="${CERTS_DIR}" \
  --execute "CREATE DATABASE IF NOT EXISTS ${DB_TESTNET}"

# Create the cmsdb user and assign privileges.
cockroach sql \
  --host="${HOST}" \
  --certs-dir="${CERTS_DIR}" \
  --execute "CREATE USER IF NOT EXISTS ${USER_CMS}"

cockroach sql \
  --host="${HOST}" \
  --certs-dir="${CERTS_DIR}" \
  --execute "GRANT CREATE, SELECT, DROP, INSERT, DELETE, UPDATE \
  ON DATABASE ${DB_MAINNET} TO  ${USER_CMS}"

cockroach sql \
  --host="${HOST}" \
  --certs-dir="${CERTS_DIR}" \
  --execute "GRANT CREATE, SELECT, DROP, INSERT, DELETE, UPDATE \
  ON DATABASE ${DB_TESTNET} TO  ${USER_CMS}"
