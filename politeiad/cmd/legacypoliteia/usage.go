// Copyright (c) 2022 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

const usageMsg = `legacypoliteia usage:

Commands
  convert  Convert git backend data into tstore backend types.

Command Usage: convert

  $ legacypoliteia convert <gitRepo>

  The convert command parses a legacy git repo, converts the data into types
  supported by the tstore backend, then writes the converted JSON data to disk.
  This data can be imported into tstore using the 'import' command.

  Arguments
  1. gitRepo     (string) Path to the legacy git repo.

  Flags
  --legacydir    (string) Path to directory that the JSON data will be written
                          to. The directory does not need to exist.
                          (default: ./legacy-politeia-data)
  --token        (string) Specify a single token whose contents will be
                          converted and saved to disk.
                          (default: "")
  --overwrite    (bool)   The conversion command will skip over a legacy
                          proposal if it is found in the legacydir, indicating
                          that it has already been converted. This flag
                          overrides that default behavior and performs the
                          conversion work again. The existing converted
                          proposal in the legacydir will be overwritten.
                          (default: false)`
