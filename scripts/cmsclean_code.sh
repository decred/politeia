#!/usr/bin/env sh

  readonly ROOT_CERTS_DIR="${HOME}/.cockroachdb/certs/clients/root"

  cockroach sql \
    --certs-dir="${ROOT_CERTS_DIR}" \
    --execute "DROP TABLE IF EXISTS users_testnet3.cms_code_stats"
\
 