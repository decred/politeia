Launch politead
```
dep ensure
go install -v ./... && LOGFLAGS=shortfile politeiad --testnet --rpcuser=user --rpcpass=pass --gittrace
```

Install politeia
```
cd politeiad/cmd/politeia
go install
```

Run example scripts
```
cd examples/bugbounty
bash -x report_bug.sh
```

Example output:
```
+ . settings.sh
++ RPCHOST=127.0.0.1
++ RPCUSER=user
++ RPCPASS=pass
++ EFLAGS='-v -testnet'
++ USERFLAGS='-v -testnet -rpchost 127.0.0.1'
++ ADMINFLAGS='-v -testnet -rpchost 127.0.0.1 -rpcuser user -rpcpass pass'
+ politeia -v -testnet -rpchost 127.0.0.1 new '{"name":"Marco", "description":"Bad bug #1"}' badbug1.txt
00: 512cd8bc7980a6186fd36e7a095310f33b8cda1a696185bf77c6de97a7f2cfcb badbug1.txt text/plain; charset=utf-8
Record submitted
  Censorship record:
    Merkle   : 512cd8bc7980a6186fd36e7a095310f33b8cda1a696185bf77c6de97a7f2cfcb
    Token    : 141aed9b800e49bb8db9b30d32994a1b56154bc3c64842e177ba80e0e1715883
    Signature: 643e142d24004883a824bb42c083622bfb0069de9659ae0dd3ee296bc20cc1a9d07c7dd6e97b6fb01d28240aaa34405df42eec15febcdda57b98eb109f5bf30d
```
