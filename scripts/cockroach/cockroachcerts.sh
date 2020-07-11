#!/usr/bin/env bash
# This script creates the certificates required to run a CockroachDB node
# locally. This includes creating a CA certificate, a node certificate, and a
# client certificate for the root user. The root user is used to open a sql
# shelL.
#
# More information on CockroachDB certificate usage can be found at:
# https://www.cockroachlabs.com/docs/stable/create-security-certificates.html

set -ex

# Database usernames
readonly USER_POLITEIAD="politeiad"
readonly USER_POLITEIAWWW="politeiawww"

# COCKROACHDB_DIR is where all of the certificates will be created.
COCKROACHDB_DIR=$1
if [ "${COCKROACHDB_DIR}" == "" ]; then
  COCKROACHDB_DIR="${HOME}/.cockroachdb"
fi

# Create cockroachdb directories.
mkdir -p "${COCKROACHDB_DIR}/certs/node"
mkdir -p "${COCKROACHDB_DIR}/certs/clients/root"
mkdir -p "${COCKROACHDB_DIR}/certs/clients/${USER_POLITEIAD}"
mkdir -p "${COCKROACHDB_DIR}/certs/clients/${USER_POLITEIAWWW}"


# Create CA certificate and key.
cockroach cert create-ca \
  --certs-dir="${COCKROACHDB_DIR}/certs" \
  --ca-key="${COCKROACHDB_DIR}/ca.key" \

# Create the node certificate and key.  These files, node.crt and node.key,
# will be used to secure communication between nodes. You would generate these
# separately for each node with a unique addresses.  The node certificate that
# is generated here is for a CockroachDB node that is running locally.  See the
# CockroachDB docs for instructions on generating node certificates for a
# CockroachDB cluster.
# https://www.cockroachlabs.com/docs/stable/manual-deployment.html
cp "${COCKROACHDB_DIR}/certs/ca.crt" "${COCKROACHDB_DIR}/certs/node"
cockroach cert create-node localhost \
  $(hostname) \
  localhost \
  127.0.0.1 \
  --certs-dir="${COCKROACHDB_DIR}/certs/node" \
  --ca-key="${COCKROACHDB_DIR}/ca.key"

# Create the client certificate and key for the root user.  These files,
# client.root.crt and client.root.key, will be used to secure communication
# between the built-in SQL shell and the cluster.
cp "${COCKROACHDB_DIR}/certs/ca.crt" "${COCKROACHDB_DIR}/certs/clients/root"
cockroach cert create-client root \
  --certs-dir="${COCKROACHDB_DIR}/certs/clients/root" \
  --ca-key="${COCKROACHDB_DIR}/ca.key"

# Create the client certificate and key for the politeiad user.
cp "${COCKROACHDB_DIR}/certs/ca.crt" \
  "${COCKROACHDB_DIR}/certs/clients/${USER_POLITEIAD}"

cockroach cert create-client ${USER_POLITEIAD} \
  --certs-dir="${COCKROACHDB_DIR}/certs/clients/${USER_POLITEIAD}" \
  --ca-key="${COCKROACHDB_DIR}/ca.key"

# Create the client certificate and key for politeiawww user.
cp "${COCKROACHDB_DIR}/certs/ca.crt" \
  "${COCKROACHDB_DIR}/certs/clients/${USER_POLITEIAWWW}"

cockroach cert create-client ${USER_POLITEIAWWW} \
  --certs-dir="${COCKROACHDB_DIR}/certs/clients/${USER_POLITEIAWWW}" \
  --ca-key="${COCKROACHDB_DIR}/ca.key"
