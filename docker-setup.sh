mkdir ~/.politeiad ~/.politeiawww
cd ~/
wget -qO- https://binaries.cockroachdb.com/cockroach-v19.1.0.linux-amd64.tgz | tar  xvz
cp -i cockroach-v19.1.0.linux-amd64/cockroach /go/bin

cat >> ~/.politeiad/politeiad.conf <<EOL
rpcuser=user
rpcpass=pass
testnet=true
enablecache=true
cachehost=localhost:26257
cacherootcert="~/.cockroachdb/certs/clients/politeiad/ca.crt"
cachecert="~/.cockroachdb/certs/clients/politeiad/client.politeiad.crt"
cachekey="~/.cockroachdb/certs/clients/politeiad/client.politeiad.key"
EOL

cat >> ~/.politeiawww/politeiawww.conf <<EOL
mode=piwww
rpchost=127.0.0.1
rpcuser=user
rpcpass=pass
rpccert="~/.politeiad/https.cert"
testnet=true
paywallxpub=tpubVobLtToNtTq6TZNw4raWQok35PRPZou53vegZqNubtBTJMMFmuMpWybFCfweJ52N8uZJPZZdHE5SRnBBuuRPfC5jdNstfKjiAs8JtbYG9jx
paywallamount=10000000
dbhost=localhost:26257
dbrootcert="~/.cockroachdb/certs/clients/politeiawww/ca.crt"
dbcert="~/.cockroachdb/certs/clients/politeiawww/client.politeiawww.crt"
dbkey="~/.cockroachdb/certs/clients/politeiawww/client.politeiawww.key"
EOL

cat >> /go/bin/picachedb <<EOL
#!/bin/bash

cockroach start \
  --certs-dir=${HOME}/.cockroachdb/certs/node \
  --listen-addr=localhost \
  --store=${HOME}/.cockroachdb/data
EOL
chmod a+x /go/bin/picachedb

cat >> /go/bin/pi <<EOL
#!/bin/bash

picachedb &
sleep 3s
politeiad &
sleep 3s
politeiawww
EOL
chmod a+x /go/bin/pi

cat >> /go/bin/pidataload <<EOL
#!/bin/bash

picachedb &
sleep 3s
politeiawww_dataload --verbose || true
EOL
chmod a+x /go/bin/pidataload


cd $GOPATH/src/github.com/decred/politeia
./scripts/cockroachcerts.sh

picachedb &

sleep 5s;

cd $GOPATH/src/github.com/decred/politeia
./scripts/cachesetup.sh

cd $GOPATH/src/github.com/decred/politeia
./scripts/cmssetup.sh

cd $GOPATH/src/github.com/decred/politeia

export GO111MODULE=on
go install -v ./...


politeiad &
sleep 5s;

politeiawww --fetchidentity --interactive=i-know-this-is-a-bad-idea

politeiawww &
sleep 5s;

cd $GOPATH/src/github.com/decred/politeia
./scripts/userdbsetup.sh

politeiawww_dbutil -createkey

cat >> ~/.politeiawww/politeiawww.conf <<EOL
encryptionkey=~/.politeiawww/sbox.key
userdb=cockroachdb
EOL
