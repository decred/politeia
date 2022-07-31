#!/usr/bin/env sh

# This script sets up the MySQL databases for the proposals app user and
# assigns user privileges.

# Accepts environment variables:
# - HOST: The hostname of the MySQL server (default: localhost)
# - PORT: The port that the MySQL server is listening on (default: 3306)
# - ROOT_USER: A user with sufficient rights to create new users and create
#   the app user database (default: root)
# - ROOT_PASSWORD: The password for the ROOT_USER (default: none)
# - APP_DB: The database name of the app database that will be created
#   (default: dcrpro_testnet3)
# - APP_USER: The name of the MySQL user that will be created for the app
#   (default: dcrpro)
# - APP_PASSWORD: The password for the APP_USER that will be created
#   (default: dcrpropass)
# - APP_HOST: The host that the APP_USER will connect from; use '%' as a
#   wildcard (default: localhost)

# Set any unset environment variables to the defaults
[ -z ${HOST+x} ] && HOST="localhost"
[ -z ${PORT+x} ] && PORT="3306"
[ -z ${ROOT_USER+x} ] && ROOT_USER="root"
[ -z ${ROOT_PASSWORD+x} ] && ROOT_PASSWORD=""
[ -z ${APP_DB+x} ] && APP_DB="dcrpro_testnet3"
[ -z ${APP_USER+x} ] && APP_USER="dcrpro"
[ -z ${APP_PASSWORD+x} ] && APP_PASSWORD="dcrpropass"
[ -z ${APP_HOST+x} ] && APP_HOST="localhost"

# Run all commands as the MySQL root user
flags="-u "${ROOT_USER}" -p"${ROOT_PASSWORD}" --verbose \
  --host ${HOST} --port ${PORT}"

# Create the database
mysql ${flags} -e "CREATE DATABASE IF NOT EXISTS ${APP_DB};"

# Create the app user
mysql ${flags} -e \
  "CREATE USER IF NOT EXISTS '${APP_USER}'@'${APP_HOST}' \
   IDENTIFIED BY '${APP_PASSWORD}';"

# Grant user privileges
mysql ${flags} -e \
  "GRANT ALL PRIVILEGES ON ${APP_DB}.* \
   TO '${APP_USER}'@'${APP_HOST}';"
