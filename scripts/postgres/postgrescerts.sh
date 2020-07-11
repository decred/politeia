#!/usr/bin/env bash
# This script creates the certificates required to run a PostgreSQL node
# locally. This includes creating a CA certificate, a node certificate, and two
# client certificates one for politeiad, and the second for politeiawww
# NOTE: this scripts creates and copies over the server files (root.crt, 
# server.key & root.crt) to postgres' data dir, is uses $PGDATA environment
# variable to determine where to copy the files to, make sure it's exported
# before running the script.
#
# More information on PostgreSQL ssl connection usage can be found at:
# https://www.postgresql.org/docs/9.5/ssl-tcp.html

set -ex

# Database usernames
readonly USER_POLITEIAD="politeiad"
readonly USER_POLITEIAWWW="politeiawww"

# POSTGRES_DIR is where all of the certificates will be created.
POSTGRESCERTS_DIR=$1
if [ "${POSTGRESCERTS_DIR}" == "" ]; then
  POSTGRESCERTS_DIR="${HOME}/.postgresql"
fi

# Create postgresdb clients directories.
mkdir -p "${POSTGRESCERTS_DIR}/certs/clients/${USER_POLITEIAD}"
mkdir -p "${POSTGRESCERTS_DIR}/certs/clients/${USER_POLITEIAWWW}"

# Create CA private key
openssl genrsa -des3 -out root.key 4096
#Remove a passphrase
openssl rsa -in root.key -out root.key

# Create a root Certificate Authority (CA)
openssl \
    req -new -x509 \
    -days 365 \
    -subj "/CN=CA" \
    -key root.key \
    -out root.crt

# Create server key
openssl genrsa -des3 -out server.key 4096
#Remove a passphrase
openssl rsa -in server.key -out server.key

# Create a root certificate signing request
openssl \
    req -new \
    -key server.key \
    -subj "/CN=localhost" \
    -text \
    -out server.csr

# Create server certificate
openssl \
    x509 -req \
    -in server.csr \
    -text \
    -days 365 \
    -CA root.crt \
    -CAkey root.key \
    -CAcreateserial \
    -out server.crt

# Copy server.key, server.crt & root.crt to postgres' data dir as discribed in
# PostgresSQL ssl connection documentation, it uses environment variable PGDATA
# as postgres' data dir
sudo -u postgres cp server.key server.crt root.crt $PGDATA

# Create client key for politeiad
openssl genrsa -out politeiad.client.key 4096
#Remove a passphrase
openssl rsa -in politeiad.client.key -out politeiad.client.key

chmod og-rwx politeiad.client.key

# Create client certificate signing request
# Note: CN should be equal to db username
openssl \
    req -new \
    -key politeiad.client.key \
    -subj "/CN=${USER_POLITEIAD}" \
    -out politeiad.client.csr

# Create client certificate
openssl \
    x509 -req \
    -in politeiad.client.csr \
    -CA root.crt \
    -CAkey root.key \
    -CAcreateserial \
    -days 365 \
    -text \
    -out politeiad.client.crt

# Copy client to certs dir
cp politeiad.client.key politeiad.client.crt root.crt \
  ${POSTGRESCERTS_DIR}/certs/clients/${USER_POLITEIAD}
    
# Create client key for politeiawww
openssl genrsa -out politeiawww.client.key 4096
#Remove a passphrase
openssl rsa -in politeiawww.client.key -out politeiawww.client.key

chmod og-rwx politeiawww.client.key

# Create client certificate signing request
# Note: CN should be equal to db username
openssl \
    req -new \
    -key politeiawww.client.key \
    -subj "/CN=${USER_POLITEIAWWW}" \
    -out politeiawww.client.csr

# Create client certificate
openssl \
    x509 -req \
    -in politeiawww.client.csr \
    -CA root.crt \
    -CAkey root.key \
    -CAcreateserial \
    -days 365 \
    -text \
    -out politeiawww.client.crt

# Copy client to certs dir
cp politeiawww.client.key politeiawww.client.crt root.crt \
  ${POSTGRESCERTS_DIR}/certs/clients/${USER_POLITEIAWWW}

# "On Unix systems, the permissions on 
# server.key must disallow any access to world or group"
# Source: PostgresSQL docs - link above
#
sudo chmod og-rwx $PGDATA/server.key
sudo chmod og-rwx $POSTGRESCERTS_DIR/certs/clients/${USER_POLITEIAWWW}/${USER_POLITEIAWWW}.client.key
sudo chmod og-rwx $POSTGRESCERTS_DIR/certs/clients/${USER_POLITEIAD}/${USER_POLITEIAD}.client.key

# Cleanup
rm *.crt *.key *.srl *.csr


