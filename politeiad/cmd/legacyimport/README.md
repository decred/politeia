# legacyimport

`legacyimport` is a tool that will be used to import the git backend legacy records
into the new tlog backend. This tool will only be used once.

## Considerations

- We decided to import only the latest version of each record into tlog, and save it as
a version 1/iteration 1 record. If one wishes to check further versions of a finished
legacy record, the git repo will be available.

- cast vote signatures cannot be verified using the current politeia public key. 
should use "a70134196c3cdf3f85f8af6abaa38c15feb7bccf5e6d3db6212358363465e502".

- vote details medatada cannot be sig verified with the new tlog backend because
of significant data changes

## Usage 

`leagcyimport`.


##