#!/usr/bin/env bash

readonly ROOT_CERTS_DIR="${HOME}/.cockroachdb/certs/clients/root"

rm -rf ~/.politeiawww/data/testnet3/
rm -rf ~/.politeiad/data/testnet3/
rm -rf ~/.piwww/data
rm -rf ~/.cmswww/data

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

