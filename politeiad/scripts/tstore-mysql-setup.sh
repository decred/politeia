#!/usr/bin/env sh

# Accepts environment variables:
# - MYSQL_HOST: The hostname of the MySQL server (default: localhost).
# - MYSQL_PORT: The port the MySQL server is listening on (default: 3306).
# - MYSQL_ROOT_USER: A user with sufficient rights to create new users and
#   create/drop the politeiad database (default: root).
# - MYSQL_ROOT_PASSWORD: The password for the user defined by MYSQL_ROOT_USER 
#   (requed, default: none).
# - MYSQL_POLITEIAD_PASSWORD: The password for the politeiad user that will be
#   created during this script (required, default: none).
# - MYSQL_TRILLIAN_PASSWORD: The password for the trillian user that will be
#   created during this script (required, default: none).
# - MYSQL_USER_HOST: The host that the politeiad and trillian users will
#   connect from; use '%' as a wildcard (default: localhost).

# Set unset environment variables to defaults
[ -z ${MYSQL_HOST+x} ] && MYSQL_HOST="localhost"
[ -z ${MYSQL_PORT+x} ] && MYSQL_PORT="3306"
[ -z ${MYSQL_ROOT_USER+x} ] && MYSQL_ROOT_USER="root"
[ -z ${MYSQL_ROOT_PASSWORD+x} ] && MYSQL_ROOT_PASSWORD=""
[ -z ${MYSQL_POLITEIAD_PASSWORD+x} ] && MYSQL_POLITEIAD_PASSWORD=""
[ -z ${MYSQL_TRILLIAN_PASSWORD+x} ] && MYSQL_TRILLIAN_PASSWORD=""
[ -z ${MYSQL_USER_HOST+x} ] && MYSQL_USER_HOST="localhost"

flags="-u "${MYSQL_ROOT_USER}" -p"${MYSQL_ROOT_PASSWORD}" --verbose \
  --host ${MYSQL_HOST} --port ${MYSQL_PORT}"

# Database users
politeiad="politeiad"
trillian="trillian"

# Database names
testnet_kv="testnet3_kv"
mainnet_kv="mainnet_kv"

# Setup database users
mysql ${flags} -e \
  "CREATE USER IF NOT EXISTS '${politeiad}'@'${MYSQL_USER_HOST}' \
  IDENTIFIED BY '${MYSQL_POLITEIAD_PASSWORD}'"

mysql ${flags} -e \
  "CREATE USER IF NOT EXISTS '${trillian}'@'${MYSQL_USER_HOST}' \
  IDENTIFIED BY '${MYSQL_TRILLIAN_PASSWORD}'"

# Setup kv databases. The trillian script creates the trillian databases.
mysql ${flags} -e "CREATE DATABASE IF NOT EXISTS ${testnet_kv};"
mysql ${flags} -e "CREATE DATABASE IF NOT EXISTS ${mainnet_kv};"

mysql ${flags} -e \
  "GRANT ALL ON ${testnet_kv}.* TO '${politeiad}'@'${MYSQL_USER_HOST}'"
mysql ${flags} -e \
  "GRANT ALL ON ${mainnet_kv}.* TO '${politeiad}'@'${MYSQL_USER_HOST}'"
