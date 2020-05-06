#!/usr/bin/env sh

NETWORK=$1
if [ "${NETWORK}" == "" ]; then
  NETWORK="testnet3"
fi

POLITEIAWWWDIR=$2
if [ "${POLITEIAWWWDIR}" == "" ]; then
  POLITEIAWWWDIR=".politeiawww"
fi

PIDDIR=$3
if [ "${PIDDIR}" == "" ]; then
  PIDDIR=".politeiad"
fi

PIWWWDIR=$4
if [ "${PIWWWDIR}" == "" ]; then
  PIWWWDIR=".piwwww"
fi

CMSWWWDIR=$4
if [ "${CMSWWWDIR}" == "" ]; then
  CMSWWWDIR=".cmswww"
fi

echo "Warning: about to delete the following directories:
${HOME}/${POLITEIAWWWDIR}/data/${NETWORK}/
${HOME}/${PIDDIR}/data/${NETWORK}/
${HOME}/${PIWWWDIR}/data
${HOME}/${CMSWWWDIR}/data"
read -p "Are you sure? [Y/N]: " -n 1 -r
echo # Print newline following the above prompt

if [ -z ${REPLY+x} ] || [[ $REPLY =~ ^[Yy]$ ]]
then


  rm -rf ${HOME}/${POLITEIAWWWDIR}/data/${NETWORK}/
  rm -rf ${HOME}/${PIDDIR}/data/${NETWORK}/
  rm -rf ${HOME}/${PIWWWDIR}/data
  rm -rf ${HOME}/${CMSWWWDIR}/data

  readonly ROOT_CERTS_DIR="${HOME}/.cockroachdb/certs/clients/root"

  cockroach sql \
    --certs-dir="${ROOT_CERTS_DIR}" \
    --execute "DROP TABLE IF EXISTS users_testnet3.users, \
    users_testnet3.identities, users_testnet3.key_value, \
    users_testnet3.cms_users, users_testnet3.sessions"

  cockroach sql \
    --certs-dir="${ROOT_CERTS_DIR}" \
    --execute "DROP TABLE IF EXISTS cms_testnet3.exchange_rates, \
    cms_testnet3.invoice_changes, cms_testnet3.invoices, \
    cms_testnet3.line_items, cms_testnet3.payments"
 fi