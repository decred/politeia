// Copyright (c) 2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

const usageMsg = `legacypoliteia usage:

Commands
  convert  Convert git backend data into tstore backend types.
  import   Import converted results into tstore.

Command Usage

  $ legacypoliteia convert <gitRepo>

    The convert command parses a legacy git repo, converts the data into types
    supported by the tstore backend, then writes the converted JSON data to
    disk. This data can be imported into tstore using the 'import' command.

    Arguments
    1. gitRepo     (string) Path to the legacy git repo.

    Flags
    --legacydir    (string) Path to direcory that the JSON data will be written
                            to. The directory does not need to exist.
                            (default: ./legacy-politeia-data)
    --skipcomments (bool)   Skip parsing the comment journals. (default: false)
    --skipballots  (bool)   Skip parsing the ballot journals. (default: false)
    --ballotlimit  (int)    Limit the number of votes when parsing the ballot
                            journals. A limit of 0 will result in all ballots
                            being parsed. (default: 0)
    --userid       (string) Replace the user IDs in the parsed data with the
                            provided user ID. (default: "")

  $ legacypoliteia import <legacyDir>

    Import the JSON output from the 'convert' command into tstore.

    Arguments
    1. legacyDir (string) Path to the directory that contains the converted
                          legacy JSON data.

    Flags
    --tloghost (string) Host for tlog. (default: localhost:8090)
    --dbhost   (string) Host for mysql db. (default: localhost:3306)
    --dbpass   (string) Password for tlog host. (default: politeiadpass)`
