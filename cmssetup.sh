#!/usr/bin/env bash
# This script sets up the CockroachDB databases and users for the cms database.
# This includes creating the client certificates for the cms user, creating the
# corresponding database user, setting up the cms databases, and assigning user
# privileges.  
# This script requires that you have already created CockroachDB certificates
# using the cockroachcerts.sh script and that you have a CockroachDB instance
# listening on the port localhost:26258.

set -ex

# COCKROACHDB_DIR must be the same directory that was passed into the
# cockroachcerts.sh script.
readonly COCKROACHDB_DIR=$1

if [ "${COCKROACHDB_DIR}" == "" ]; then
    >&2 echo "error: missing argument CockroachDB directory"
    exit
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

# Database names.
readonly DB_MAINNET="cms_mainnet"
readonly DB_TESTNET="cms_testnet3"

# Host that the database is currently running on.
readonly HOST="localhost:26258"

# Database usernames.
readonly 	USER_CMS="invoices_cmsdb" 


# Make directory for the cms client certs.
mkdir -p "${COCKROACHDB_DIR}/certs/clients/$USER_CMS"

# Create the client certificate and key for the cmsdb user.
cp "${COCKROACHDB_DIR}/certs/ca.crt" \
  "${COCKROACHDB_DIR}/certs/clients/${USER_CMS}"

cockroach cert create-client ${USER_CMS} \
  --certs-dir="${COCKROACHDB_DIR}/certs/clients/${USER_CMS}" \
  --ca-key="${COCKROACHDB_DIR}/ca.key"


# Create the mainnet and testnet databases for the cms database.
cockroach sql \
  --host="${HOST}" \
  --certs-dir="${ROOT_CERTS_DIR}" \
  --execute "CREATE DATABASE IF NOT EXISTS ${DB_MAINNET}"

cockroach sql \
  --host="${HOST}" \
  --certs-dir="${ROOT_CERTS_DIR}" \
  --execute "CREATE DATABASE IF NOT EXISTS ${DB_TESTNET}"

# Create the cmsdb user and assign privileges.
cockroach sql \
  --host="${HOST}" \
  --certs-dir="${ROOT_CERTS_DIR}" \
  --execute "CREATE USER IF NOT EXISTS ${USER_CMS}"

cockroach sql \
  --host="${HOST}" \
  --certs-dir="${ROOT_CERTS_DIR}" \
  --execute "GRANT CREATE, SELECT, DROP, INSERT, DELETE, UPDATE \
  ON DATABASE ${DB_MAINNET} TO  ${USER_CMS}"

cockroach sql \
  --host="${HOST}" \
  --certs-dir="${ROOT_CERTS_DIR}" \
  --execute "GRANT CREATE, SELECT, DROP, INSERT, DELETE, UPDATE \
  ON DATABASE ${DB_TESTNET} TO  ${USER_CMS}"
