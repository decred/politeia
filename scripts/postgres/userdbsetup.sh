#!/usr/bin/env sh
# This script sets up the PostgreSQL databases for the politeiawww user data
# and assigns user privileges.
# This script requires that you have already created PostgreSQL certificates
# using the postgrescerts.sh script and that you have a PostgreSQL instance
# listening on the default port localhost:5432.

set -ex

# POSTGRES_DIR must be the same directory that was used with the
# cockroachcerts.sh script.
POSTGRES_DIR=$1
if [ "${POSTGRES_DIR}" = "" ]; then
  POSTGRES_DIR="${HOME}/.postgresql"
fi

# ROOT_CERTS_DIR must contain client.root.crt, client.root.key, and ca.crt.
readonly ROOT_CERTS_DIR="${POSTGRES_DIR}/certs/clients/root"

if [ ! -f "${ROOT_CERTS_DIR}/client.root.crt" ]; then
  >&2 echo "error: file not found ${ROOT_CERTS_DIR}/client.root.crt"
  exit
elif [ ! -f "${ROOT_CERTS_DIR}/client.root.key" ]; then
  >&2 echo "error: file not found ${ROOT_CERTS_DIR}/client.root.key"
  exit
elif [ ! -f "${ROOT_CERTS_DIR}/root.crt" ]; then
  >&2 echo "error: file not found ${ROOT_CERTS_DIR}/root.crt"
  exit
fi

# Database names
readonly DB_MAINNET="users_mainnet"
readonly DB_TESTNET="users_testnet3"

# Database usernames
readonly USER_POLITEIAWWW="politeiawww"

# Psql connection string
readonly CONNECTION_STRING="host=localhost \
  sslmode=verify-full  \
  sslrootcert=${ROOT_CERTS_DIR}/root.crt \
  sslcert=${ROOT_CERTS_DIR}/client.root.crt \
  sslkey=${ROOT_CERTS_DIR}/client.root.key \
  port=5432 \
  user=postgres \
  dbname=postgres"

# Create the mainnet and testnet databases for the politeiawww user data.
psql "$CONNECTION_STRING" \
  -c "CREATE DATABASE ${DB_MAINNET}"

psql "$CONNECTION_STRING" \
  -c "CREATE DATABASE ${DB_TESTNET}"

# Create the politeiawww user (if not exists) and assign privileges.
psql "$CONNECTION_STRING" \
   -c "DO \$\$ \
    BEGIN \
    CREATE USER ${USER_POLITEIAWWW}; \
    EXCEPTION WHEN duplicate_object THEN RAISE NOTICE '%, skipping', \
    SQLERRM USING ERRCODE = SQLSTATE; \
    END \
    \$\$;"

psql "$CONNECTION_STRING" \
  -c "GRANT CREATE \
  ON DATABASE ${DB_MAINNET} TO  ${USER_POLITEIAWWW}"

psql "$CONNECTION_STRING" \
  -c "GRANT CREATE \
  ON DATABASE ${DB_TESTNET} TO  ${USER_POLITEIAWWW}"
