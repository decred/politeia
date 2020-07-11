#!/usr/bin/env bash
# This script creates the certificates required to run a PostgreSQL node
# locally. This includes creating a CA certificate, a node certificate, one 
# root client to connect via cli, and two more client certificates the first
# for politeiad, the second for politeiawww.
# NOTE: this scripts creates and copies over the server files (root.crt, 
# server.key & root.crt) to postgres' data dir, is uses $PGDATA environment
# variable to determine where to copy the files to, make sure it's exported
# before running the script.
# when done creating & moving certs this script restarts postgres server
# in order to load created server certs.
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
mkdir -p "${POSTGRESCERTS_DIR}/certs/clients/root"
mkdir -p "${POSTGRESCERTS_DIR}/certs/clients/${USER_POLITEIAD}"
mkdir -p "${POSTGRESCERTS_DIR}/certs/clients/${USER_POLITEIAWWW}"

# Create a CA private key
echo "Generating root.key, please type a password:"
openssl genrsa -des3 -out root.key 4096
# Remove passphrase
echo "Removing root.key password, please re-type it:"
openssl rsa -in root.key -out root.key -passout pass:123

# Create a root Certificate Authority (CA)
openssl \
    req -new -x509 \
    -days 365 \
    -subj "/CN=CA" \
    -key root.key \
    -out root.crt

# Create server key
echo "Generating server.key, please type a password:"
openssl genrsa -des3 -out server.key 4096 -passout pass:123
#Remove a passphrase
echo "Removing server.key password, please re-type it:"
openssl rsa -in server.key -out server.key -passout pass:123

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
echo "Copying server.key server.crt root.crt to $PGDATA as postgres sys user"
sudo -u postgres cp server.key server.crt root.crt $PGDATA

# Create root client key - used to connect via cli
openssl genrsa -out client.root.key 4096
# Remove passphrase
openssl rsa -in client.root.key -out client.root.key

chmod og-rwx client.root.key

# Create client certificate signing request
# Note: CN should be equal to db username
openssl \
    req -new \
    -key client.root.key \
    -subj "/CN=postgres" \
    -out client.root.csr

# Create client certificate
openssl \
    x509 -req \
    -in client.root.csr \
    -CA root.crt \
    -CAkey root.key \
    -CAcreateserial \
    -days 365 \
    -text \
    -out client.root.crt

# Copy client to certs dir
cp client.root.key client.root.crt root.crt \
  ${POSTGRESCERTS_DIR}/certs/clients/root

# Create client key for politeiad
openssl genrsa -out client.${USER_POLITEIAD}.key 4096
# Remove passphrase
openssl rsa -in client.${USER_POLITEIAD}.key -out client.${USER_POLITEIAD}.key

chmod og-rwx client.${USER_POLITEIAD}.key

# Create client certificate signing request
# Note: CN should be equal to db username
openssl \
    req -new \
    -key client.${USER_POLITEIAD}.key \
    -subj "/CN=${USER_POLITEIAD}" \
    -out client.${USER_POLITEIAD}.csr

# Create client certificate
openssl \
    x509 -req \
    -in client.${USER_POLITEIAD}.csr \
    -CA root.crt \
    -CAkey root.key \
    -CAcreateserial \
    -days 365 \
    -text \
    -out client.${USER_POLITEIAD}.crt

# Copy client to certs dir
cp client.${USER_POLITEIAD}.key client.${USER_POLITEIAD}.crt root.crt \
  ${POSTGRESCERTS_DIR}/certs/clients/${USER_POLITEIAD}
    
# Create client key for politeiawww
openssl genrsa -out client.${USER_POLITEIAWWW}.key 4096
# Remove a passphrase
openssl rsa -in client.${USER_POLITEIAWWW}.key -out client.${USER_POLITEIAWWW}.key

chmod og-rwx client.${USER_POLITEIAWWW}.key

# Create client certificate signing request
# Note: CN should be equal to db username
openssl \
    req -new \
    -key client.${USER_POLITEIAWWW}.key \
    -subj "/CN=${USER_POLITEIAWWW}" \
    -out client.${USER_POLITEIAWWW}.csr

# Create client certificate
openssl \
    x509 -req \
    -in client.${USER_POLITEIAWWW}.csr \
    -CA root.crt \
    -CAkey root.key \
    -CAcreateserial \
    -days 365 \
    -text \
    -out client.${USER_POLITEIAWWW}.crt

# Copy client to certs dir
cp client.${USER_POLITEIAWWW}.key client.${USER_POLITEIAWWW}.crt root.crt \
  ${POSTGRESCERTS_DIR}/certs/clients/${USER_POLITEIAWWW}

# "On Unix systems, the permissions on 
# server.key must disallow any access to world or group"
# Source: PostgresSQL docs - link above
#
sudo chmod og-rwx $PGDATA/server.key
sudo chmod og-rwx $POSTGRESCERTS_DIR/certs/clients/${USER_POLITEIAWWW}/client.${USER_POLITEIAWWW}.key
sudo chmod og-rwx $POSTGRESCERTS_DIR/certs/clients/${USER_POLITEIAD}/client.${USER_POLITEIAD}.key

# Cleanup
rm *.crt *.key *.srl *.csr

# Restart postgres to load server certs
sudo -u postgres pg_ctl -D $PGDATA restart
