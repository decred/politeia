# cmswww_payment

cmswww_payment is a tool to check to ensure all payments in the connected cmsdb
have a corresponding metadata entry on an invoice record.

## Usage

You can specify the following options:

  Application options
    -testnet
          Use testnet database
    -datadir string
        politeiawww data directory
		(default osDataDir/politeiawww/data)
    -dbhost string
        CockroachDB ip:port 
		(default localhost:26257)
    -dbrootcert string
        File containing the CockroachDB SSL root cert
        (default ~/.cockroachdb/certs/clients/politeiawww/ca.crt)
    -dbcert string
        File containing the CockroachDB SSL client cert
        (default ~/.cockroachdb/certs/clients/politeiawww/client.politeiawww.crt)
    -dbkey string
        File containing the CockroachDB SSL client cert key
	    (default ~/.cockroachdb/certs/clients/politeiawww/client.politeiawww.key)
    -rpccert string
	    File containing the RPC cert to communicate with politeiad
	    (default ~/.politeiawww/rpc.cert)
	-rpcuser string
	    RPC user name for privileged commands
	    (default user)
	-rpcpass string
	    RPC password for privileged commands
	    (default pass)
	-rpchost string
	    RPC Host for politeiad
	    (default 127.0.0.1)
	-rpcport string
	    RPC Port for politeiad
	    (default 49374 / 59374)
	-identityfile
        Path to file containing the politeiad identity
	    (default ~/.politeiawww/identity.json)