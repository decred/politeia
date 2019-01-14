#!/usr/bin/env bash
# This script creates the certificates required to run a CockroachDB instance
# locally with Politeia.

set -ex

readonly COCKROACHDB_DIR=$1

if [ "${COCKROACHDB_DIR}" == "" ]; then
    >&2 echo "Error: missing argument CockroachDB directory"
    exit
fi

# Create cockroachdb directories.
mkdir -p "${COCKROACHDB_DIR}/certs"
mkdir -p "${COCKROACHDB_DIR}/data"

# Create the Certificate Authority certificate and key pair.
cockroach cert create-ca \
  --certs-dir="${COCKROACHDB_DIR}/certs" \
  --ca-key="${COCKROACHDB_DIR}/ca.key" \

# Create the node certificate and key.  These files, node.crt and node.key,
# will be used to secure communication between nodes. You would generate these
# separately for each node with a unique addresses.
cockroach cert create-node localhost \
  $(hostname) \
  --certs-dir="${COCKROACHDB_DIR}/certs" \
  --ca-key="${COCKROACHDB_DIR}/ca.key"

# Create the client certificate and key for the root user.  These files,
# client.root.crt and client.root.key, will be used to secure communication
# between the built-in SQL shell and the cluster.
cockroach cert create-client root \
  --certs-dir="${COCKROACHDB_DIR}/certs" \
  --ca-key="${COCKROACHDB_DIR}/ca.key"

# Create the client certificate and key for the politeiad user.
cockroach cert create-client politeiad \
  --certs-dir="${COCKROACHDB_DIR}/certs" \
  --ca-key="${COCKROACHDB_DIR}/ca.key"

# Create the client certificate and key for politeiawww user.
cockroach cert create-client politeiawww \
  --certs-dir="${COCKROACHDB_DIR}/certs" \
  --ca-key="${COCKROACHDB_DIR}/ca.key"
