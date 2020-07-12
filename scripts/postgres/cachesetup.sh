#!/usr/bin/env bash
# This script sets up the PostgresSQL databases for the politeiad cache and
# assigns user privileges.
# This script requires that you have already created PostgresSQL certificates
# using the postgrescerts.sh script and that you have a PostgresSQL instance
# listening on the default port localhost:5432.

set -ex

# POSTGRES_DIR must be the same directory that was used with the
# postgrescerts.sh script.
POSTGRES_DIR=$1
if [ "${POSTGRES_DIR}" == "" ]; then
  POSTGRES_DIR="${HOME}/.postgresql"
fi

# ROOT_CERTS_DIR must contain client.root.crt, client.root.key, and root.crt.
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

# Database names.
readonly DB_MAINNET="records_mainnet"
readonly DB_TESTNET="records_testnet3"

# Database usernames.
readonly USER_POLITEIAD="politeiad"
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

echo $CONNECTION_STRING

# Create the mainnet and testnet databases for the politeiad records cache.
psql "$CONNECTION_STRING" \
  -c "CREATE DATABASE ${DB_MAINNET}"

psql "$CONNECTION_STRING" \
  -c "CREATE DATABASE ${DB_TESTNET}"

# Create the politeiad user and assign privileges.
psql "$CONNECTION_STRING" \
  -c "CREATE USER ${USER_POLITEIAD}"

psql "$CONNECTION_STRING" \
  -c "GRANT CREATE \
  ON DATABASE ${DB_MAINNET} TO ${USER_POLITEIAD}"

psql "$CONNECTION_STRING" \
  -c "GRANT CREATE \
  ON DATABASE ${DB_TESTNET} TO ${USER_POLITEIAD}"

# Create politeiawww user and assign privileges.
psql "$CONNECTION_STRING" \
  -c "CREATE USER ${USER_POLITEIAWWW}"

psql "$CONNECTION_STRING" \
  -c "GRANT CONNECT ON DATABASE ${DB_MAINNET} TO ${USER_POLITEIAWWW}"

psql "$CONNECTION_STRING" \
  -c "GRANT CONNECT ON DATABASE ${DB_TESTNET} TO ${USER_POLITEIAWWW}"
