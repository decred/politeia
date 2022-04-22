// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

const usageMsg = `legacypoliteia usage:

Commands
  convert  Convert git backend data into tstore backend types.
  import   Import the converted data into a tstore backend.

Command Usage: convert

  $ legacypoliteia convert <gitRepo>

  The convert command parses a legacy git repo, converts the data into types
  supported by the tstore backend, then writes the converted JSON data to disk.
  This data can be imported into tstore using the 'import' command.

  Arguments:

  1. gitRepo   (string)  Path to the legacy git repo.

  Flags:

  --legacydir  (string)  Path to directory that the JSON data will be written
                         to. The directory does not need to exist.
                         (default: ./legacy-politeia-data)

  --token      (string)  Specify a single token whose contents will be
                         converted and saved to disk. (default: "")

  --overwrite    (bool)  The conversion command will skip over a legacy
                         proposal if it is found in the legacydir, indicating
                         that it has already been converted. This flag
                         overrides that default behavior and performs the
                         conversion work again. The existing converted
                         proposal in the legacydir will be overwritten.
                         (default: false)

Command Usage: import

  $ legacypoliteia import <legacyDir>

  Import the JSON output from the 'convert' command into tstore.

  Arguments:

  1. legacyDir  (string)  Path to the directory that contains the converted
                          legacy JSON data. This directory is written to disk
                          during the execution of the 'convert' command.
  Flags:

  --testnet     (bool)    Use the testnet database. (default: false)

  --tloghost    (string)  Host for tlog. (default: localhost:8090)

  --dbhost      (string)  Host for mysql db. (default: localhost:3306)

  --dbpass      (string)  Password for mysql politeiad user.
                          (default: politeiadpass)

  --token      (string)  Specify a single legacy token whose contents will be
                         converted and saved to disk. (default: "")`
