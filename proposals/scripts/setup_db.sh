#!/usr/bin/env sh

# This script sets up the MySQL databases for the proposals app user and
# assigns user privileges.

# Accepts environment variables:
# - MYSQL_HOST: The hostname of the MySQL server (default: localhost).
# - MYSQL_PORT: The port the MySQL server is listening on (default: 3306).
# - MYSQL_ROOT_USER: A user with sufficient rights to create new users and
#   create/drop the politeiawww user database (default: root).
# - MYSQL_ROOT_PASSWORD: The password for the user defined by MYSQL_ROOT_USER 
#   (default: none).
# - MYSQL_POLITEIAWWW_PASSWORD: The password for the politeiawww user that 
#   will be created during this script (required, default: none).
# - MYSQL_USER_HOST: The host that the politeiawww user will
#   connect from; use '%' as a wildcard (default: localhost).

# Set any unset environment variables to the defaults
[ -z ${MYSQL_HOST+x} ] && MYSQL_HOST="localhost"
[ -z ${MYSQL_PORT+x} ] && MYSQL_PORT="3306"
[ -z ${MYSQL_ROOT_USER+x} ] && MYSQL_ROOT_USER="root"
[ -z ${MYSQL_ROOT_PASSWORD+x} ] && MYSQL_ROOT_PASSWORD=""
[ -z ${MYSQL_POLITEIAWWW_PASSWORD+x} ] && MYSQL_POLITEIAWWW_PASSWORD=""
[ -z ${MYSQL_USER_HOST+x} ] && MYSQL_USER_HOST="localhost"

flags="-u "${MYSQL_ROOT_USER}" -p"${MYSQL_ROOT_PASSWORD}" --verbose \
  --host ${MYSQL_HOST} --port ${MYSQL_PORT}"

TESTNET_DB="proposals_testnet3"
DB_USER="politeiawww"

# Create the user
mysql ${flags} -e \
  "CREATE USER IF NOT EXISTS '${DB_USER}'@'${MYSQL_USER_HOST}' \
  IDENTIFIED BY '${MYSQL_POLITEIAWWW_PASSWORD}';"

# Create the databases
mysql ${flags} -e \
  "CREATE DATABASE IF NOT EXISTS ${TESTNET_DB};"

# Grant user privileges
mysql ${flags} -e \
  "GRANT ALL PRIVILEGES ON ${TESTNET_DB}.* \
  TO '${DB_USER}'@'${MYSQL_USER_HOST}';"
