package client

import (
	"context"
	"fmt"

	"github.com/decred/dcrwallet/rpc/walletrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func (c *Client) LoadWalletClient() error {
	creds, err := credentials.NewClientTLSFromFile(c.cfg.WalletCert, "")
	if err != nil {
		return err
	}

	conn, err := grpc.Dial(c.cfg.WalletHost,
		grpc.WithTransportCredentials(creds))
	if err != nil {
		return err
	}

	c.ctx = context.Background()
	c.creds = creds
	c.conn = conn
	c.wallet = walletrpc.NewWalletServiceClient(conn)
	return nil
}

func (c *Client) WalletAccounts() (*walletrpc.AccountsResponse, error) {
	if c.wallet == nil {
		return nil, fmt.Errorf("walletrpc client not loaded")
	}

	if c.cfg.Verbose {
		fmt.Printf("walletrpc %v Accounts\n", c.cfg.WalletHost)
	}

	ar, err := c.wallet.Accounts(c.ctx, &walletrpc.AccountsRequest{})
	if err != nil {
		return nil, err
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(ar)
		if err != nil {
			return nil, err
		}
	}

	return ar, nil
}

func (c *Client) CommittedTickets(ct *walletrpc.CommittedTicketsRequest) (*walletrpc.CommittedTicketsResponse, error) {
	if c.wallet == nil {
		return nil, fmt.Errorf("walletrpc client not loaded")
	}

	if c.cfg.Verbose {
		fmt.Printf("walletrpc %v CommittedTickets\n", c.cfg.WalletHost)
	}

	ctr, err := c.wallet.CommittedTickets(c.ctx, ct)
	if err != nil {
		return nil, err
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(ctr)
		if err != nil {
			return nil, err
		}
	}

	return ctr, nil
}

func (c *Client) SignMessages(sm *walletrpc.SignMessagesRequest) (*walletrpc.SignMessagesResponse, error) {
	if c.wallet == nil {
		return nil, fmt.Errorf("walletrpc client not loaded")
	}

	if c.cfg.Verbose {
		fmt.Printf("walletrpc %v SignMessages\n", c.cfg.WalletHost)
	}

	smr, err := c.wallet.SignMessages(c.ctx, sm)
	if err != nil {
		return nil, err
	}

	if c.cfg.Verbose {
		err := PrettyPrintJSON(smr)
		if err != nil {
			return nil, err
		}
	}

	return smr, nil
}
