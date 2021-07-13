#!/usr/bin/env sh

# This script sets up the MySQL databases for the politeiawww user data
# and assigns user privileges.

# Accepts environment variables:
# - MYSQL_HOST: The hostname of the MySQL server (default: localhost).
# - MYSQL_PORT: The port the MySQL server is listening on (default: 3306).
# - MYSQL_ROOT_USER: A user with sufficient rights to create new users and
#   create/drop the politeiawww user database (default: root).
# - MYSQL_ROOT_PASSWORD: The password for the user defined by MYSQL_ROOT_USER 
#   (default: none).
# - MYSQL_POLITEIAWWW_PASSWORD: The password for the politeiad user that 
#   will be created during this script (required, default: none).
# - MYSQL_USER_HOST: The host that the politeiawww user will
#   connect from; use '%' as a wildcard (default: localhost).

# Set unset environment variables to defaults.
[ -z ${MYSQL_HOST+x} ] && MYSQL_HOST="localhost"
[ -z ${MYSQL_PORT+x} ] && MYSQL_PORT="3306"
[ -z ${MYSQL_ROOT_USER+x} ] && MYSQL_ROOT_USER="root"
[ -z ${MYSQL_ROOT_PASSWORD+x} ] && MYSQL_ROOT_PASSWORD=""
[ -z ${MYSQL_POLITEIAWWW_PASSWORD+x} ] && MYSQL_POLITEIAWWW_PASSWORD=""
[ -z ${MYSQL_USER_HOST+x} ] && MYSQL_USER_HOST="localhost"

flags="-u "${MYSQL_ROOT_USER}" -p"${MYSQL_ROOT_PASSWORD}" --verbose \
  --host ${MYSQL_HOST} --port ${MYSQL_PORT}"

# Database names.
DB_MAINNET="users_mainnet"
DB_TESTNET="users_testnet3"

# Database usernames.
USER_POLITEIAWWW="politeiawww"

# Create politeiawww user.
mysql ${flags} -e \
  "CREATE USER IF NOT EXISTS '${USER_POLITEIAWWW}'@'${MYSQL_USER_HOST}' \
  IDENTIFIED BY '${MYSQL_POLITEIAWWW_PASSWORD}';"

# Create the mainnet and testnet databases for the politeiawww user data.
mysql ${flags} -e \
  "CREATE DATABASE IF NOT EXISTS ${DB_MAINNET};"

mysql ${flags} -e \
  "CREATE DATABASE IF NOT EXISTS ${DB_TESTNET};"

# Grant politeiawww user privileges.
mysql ${flags} -e \
  "GRANT ALL PRIVILEGES ON ${DB_MAINNET}.* \
  TO '${USER_POLITEIAWWW}'@'${MYSQL_USER_HOST}';"

mysql ${flags} -e \
  "GRANT ALL PRIVILEGES ON ${DB_TESTNET}.* \
  TO '${USER_POLITEIAWWW}'@'${MYSQL_USER_HOST}';"

