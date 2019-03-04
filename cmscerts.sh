#!/usr/bin/env bash
# This script creates the certificates required to run a CockroachDB instance
# locally as a cms database.  
#
# More information on CockroachDB certificate usage can be found at:
# https://www.cockroachlabs.com/docs/stable/create-security-certificates.html

set -ex

# COCKROACHDB_DIR is where all of the certificates will be created.
readonly COCKROACHDB_DIR=$1

# Database user names.
readonly USER_CMS="invoices_cmsdb"

if [ "${COCKROACHDB_DIR}" == "" ]; then
    >&2 echo "Error: missing argument CockroachDB directory"
    exit
fi

# Create cockroachdb directories.
mkdir -p "${COCKROACHDB_DIR}/certs/node"
mkdir -p "${COCKROACHDB_DIR}/certs/clients/root"
mkdir -p "${COCKROACHDB_DIR}/certs/clients/$USER_CMS"
mkdir -p "${COCKROACHDB_DIR}/data"

# Create the client certificate and key for the cmsdb user.
cp ${COCKROACHDB_DIR}/certs/ca.crt \
  ${COCKROACHDB_DIR}/certs/clients/${USER_CMS}

cockroach cert create-client ${USER_CMS} \
  --certs-dir="${COCKROACHDB_DIR}/certs/clients/${USER_CMS}" \
  --ca-key="${COCKROACHDB_DIR}/ca.key"