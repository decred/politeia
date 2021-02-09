// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"

	"decred.org/dcrwallet/rpc/walletrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type dcrwalletClient struct {
	conn   *grpc.ClientConn
	wallet walletrpc.WalletServiceClient
}

func newDcrwalletClient(walletHost, walletCert, clientCert, clientKey string) (*dcrwalletClient, error) {
	serverCAs := x509.NewCertPool()
	serverCert, err := ioutil.ReadFile(walletCert)
	if err != nil {
		return nil, err
	}
	if !serverCAs.AppendCertsFromPEM(serverCert) {
		return nil, fmt.Errorf("no certificates found in %v",
			walletCert)
	}
	keypair, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, err
	}
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{keypair},
		RootCAs:      serverCAs,
	})
	conn, err := grpc.Dial(walletHost, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	return &dcrwalletClient{
		conn:   conn,
		wallet: walletrpc.NewWalletServiceClient(conn),
	}, nil
}
