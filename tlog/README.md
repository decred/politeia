# trillian test platform

tserver and tclient provide a test platform for google trillian
https://github.com/google/trillian

# trillian quick setup

Setup `MySQL` with an empty root password. This is obviously only for testing!

```
mkdir $GOPATH/src/github.com/google/
cd $GOPATH/src/github.com/google/
git clone git@github.com:google/trillian.git
cd trillian
go get -t -u -v ./...
```

Reset the test database
```
./scripts/resetdb.sh
```

Launch log server
```
trillian_log_server --logtostderr ...
```

Launch log signer daemom
```
trillian_log_signer --logtostderr --force_master --http_endpoint=localhost:8092 --rpc_endpoint=localhost:8093 --batch_size=1000 --sequencer_guard_window=0 --sequencer_interval=200ms
```

# tserver

Launch `tserver`
```
tserver --testnet
```

# Add new record

```
tclient --testnet put README.md
```
