## legacy

`legacyimport` is a tool that will be used to import the legacy records from
the git backend into tlog. It opens a connection with tstore and inserts the
records and blobs manually, bypassing backend validations.

The tool has two commands:

- `dump`
- `import`

### Flags

Application flags:

`--path`        - Path to git record repository. This flag is mandatory.
`--comments`    - Enable `comments.journal` parsing.
  `default: false`
`--ballot`      - Enable `ballot.journal` parsing.
  `default: false`
`--ballotCount` - Limits the number of votes to parse from `ballot.journal`.
  `default: 0 (all)`
`--userid`      - Replace userid data of blobs with a userid from the localdb.
  `default: "" (maintain userid from gitbe payloads)`

Connection to tstore/mysql flags:

`--tloghost`    - Host for tlog.
  `default: localhost:8090`
`--tlogpass`    - Password for tlog host.
  `default: tlogpass`
`--dbhost`      - Host for mysql db.
  `default: localhost:3306`
`--dbpass`    - Password for tlog host.
  `default: politeiadpass`


Notes: 

Limiting the ballot count is useful for testing since parsing the whole
ballot journal takes a few hours. 

A userid from a localdb must be set in order to test the legacy import locally.
This is because `politeiawww` will throw a `user not found` error when it tries
to locally fetch userid's coming from the git records.

##### Usage

Testing scenario importing comments journal and ten cast votes from the ballot 
journal: 

`legacyimport --path=/path/to/repo 
  \ --comments 
  \ --ballot 
  \ --ballotCount=10 
  \ --userid="<uuid>"`

Production scenario fully importing all data from legacy records into tstore:

`legacyimport --path=/path/to/repo 
  \ --comments 
  \ --ballot`

### Considerations

- Since the `recordmetadata.json` data struct was never signed in the first
place, it was decided to replace the `Token` field from this struct for the
newly created tstore token, instead of the legacy gitbe token, when importing
the records. This solves a lot of functionality problems that arise by having
the recordmetadata pointing to a legacy gitbe token.

- The vote parameter options from vote details struct was also updated to
reference the newly created tstore token, in order to preserve summary fetching
functionality. This struct did not exist on gitbe and therefore we do not lose
any signature verification capabilities by doing this.

- It was decided to import only the latest version of each record into tstore, 
and save it as a version 1 record. If one wishes to check further versions of
a finished legacy record, the git repo will be available.

- Legacy signatures cannot be verified using the current politeia public key.
The key that should be used for verifying legacy record signatures is:

`a70134196c3cdf3f85f8af6abaa38c15feb7bccf5e6d3db6212358363465e502`

- Some signature verification capabilities were lost due to significant data
changes and/or the data included on the signature's message. Therefore, below
is a list of legacy structs we are able to verify on tstore backend, and the
ones we are not:

##### Verified structs:
  - cast vote details
  - auth details

##### Not verified structs:
  - record
  - censorship record
  - user metadata
  - status change
  - vote details 
  - comment
  - comment del
