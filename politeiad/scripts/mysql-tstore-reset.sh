#!/usr/bin/env sh

# Accepts environment variables:
# - MYSQL_HOST: The hostname of the MySQL server (default: localhost).
# - MYSQL_PORT: The port the MySQL server is listening on (default: 3306).
# - MYSQL_ROOT_USER: A user with sufficient rights to create new users and
#   create/drop the politeiad database (default: root).
# - MYSQL_ROOT_PASSWORD: The password for the user defined by MYSQL_ROOT_USER 
#   (requed, default: none).
# - MYSQL_USER_HOST: The host that the politeiad and trillian users will
#   connect from; use '%' as a wildcard (default: localhost).
# - POLITEIAD_DIR: politeiad application directory. This will vary depending
#   on you operating system (default: ${HOME}/.politeiad).

# Set unset environment variables to defaults
[ -z ${MYSQL_HOST+x} ] && MYSQL_HOST="localhost"
[ -z ${MYSQL_PORT+x} ] && MYSQL_PORT="3306"
[ -z ${MYSQL_ROOT_USER+x} ] && MYSQL_ROOT_USER="root"
[ -z ${MYSQL_ROOT_PASSWORD+x} ] && MYSQL_ROOT_PASSWORD=""
[ -z ${MYSQL_USER_HOST+x} ] && MYSQL_USER_HOST="localhost"
[ -z ${POLITEIAD_DIR+x} ] && POLITEIAD_DIR="${HOME}/.politeiad"

flags="-u "${MYSQL_ROOT_USER}" -p"${MYSQL_ROOT_PASSWORD}" --verbose \
  --host ${MYSQL_HOST} --port ${MYSQL_PORT}"

# Database users
politeiad="politeiad"

# Database names
testnet_kv="testnet3_kv"

# Delete databases
mysql ${flags} -e "DROP DATABASE IF EXISTS ${testnet_kv};"

# Setup kv databases. The trillian script creates the trillian databases.
mysql ${flags} -e "CREATE DATABASE ${testnet_kv};"

mysql ${flags} -e \
  "GRANT ALL ON ${testnet_kv}.* TO '${politeiad}'@'${MYSQL_USER_HOST}'"

# Delete cached politeiad data
politeiad_data_dir="${POLITEIAD_DIR}/data/testnet3/"
echo "Warning: about to delete the following directories:
${politeiad_data_dir}"
read -p "Continue? [Y/N] " answer
case $answer in
  yes|Yes|y)
    rm -rf ${politeiad_data_dir}
    ;;
  no|n)
    echo "Delete aborted"
    ;;
esac

echo "politeiad testnet reset complete!"
echo "The trillian logs must be reset using the trillian script. See docs."
echo "Mainnet politeiad resets must be done manually."

