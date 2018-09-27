# politeia_verify

politeia_verify is a simple tool that allows anyone to independently verify that
Politeia has received your proposal. You just need to provide the Politeia
server's public key, the proposal's censorship token and signature, and the
proposal files.

## Usage

There are 2 methods of input:

```
politeia_verify [options] <filenames...>

Options:
 -k       Politiea's public server key
 -t       Record censorship token
 -s       Record censorship signature
 -v       Verbose output
 -jsonin  A path to a JSON file which represents the record. If this
          option is set, the other input options (-k, -t, -s) should
          not be provided.
 -jsonout JSON output

Filenames: One or more paths to the markdown and image files that
           make up the record.
```

Example:

```
politeia_verify -v -k dfd6caacf0bbe5725efc67e703e912c37931b4edbf17122947a1e0fcd9755f6d -t 6284c5f8fba5665373b8e6651ebc8747b289fed242d2f880f64a284496bb4ca8 -s 82d69b4ec83d2a732fe92028dbf78853d0814aeb4fcf0ff597c110c8843720951f7b9fae4305b0f1d9346c39bc960a364590236f9e0871f6f79860fc57d4c70 proposal.md
Proposal successfully verified.
```

If the proposal fails to verify, it will return an error:

```
politeia_verify -v -k xfd6caacf0bbe5725efc67e703e912c37931b4edbf17122947a1e0fcd9755f6d -t 6284c5f8fba5665373b8e6651ebc8747b289fed242d2f880f64a284496bb4ca8 -s 82d69b4ec83d2a732fe92028dbf78853d0814aeb4fcf0ff597c110c8843720951f7b9fae4305b0f1d9346c39bc960a364590236f9e0871f6f79860fc57d4c70 proposal.md
Proposal failed verification. Please ensure the public key and merkle are correct.
  Merkle: 0dd10219cd79342198085cbe6f737bd54efe119b24c84cbc053023ed6b7da4c8
```
