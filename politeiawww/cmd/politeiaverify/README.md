# politeiaverify

`politeiaverify` is a tool that allows anyone to independently verify the
validity of data submitted to Politeia. This includes:
- Verifying the censorship record of a record submission. A censorship record
  provides cryptographic proof that a record was received by Politeia.
- Verifying the receipts for non-record data (ex. comments). The receipts
  provide cryptographic proof the non-record data was received by Politeia. 
- Verifying user signatures. Anytime a user submits data to Politeia they must
  sign the data using a key pair that is specific to the user. The public key
  and signature is saved along with the data, providing cryptographic proof
  that the data was submitted by the user.
- Verifying timestamps. All data submitted to Politeia is timestamped onto
  the Decred blockchain. A timestamp provides cryptographic proof that data
  existed at block height x and has not been altered since then.

## Usage

```
politeiaverify [flags] <filepaths>...`

Options:
 -k       Politiea's public server key
 -t       Record censorship token
 -s       Record censorship signature
```

## Verifying politeiagui bundles

Any of the file bundles that are available for download in politeiagui can
be passed into `politeiaverify` directly. These files contain all the data
needed to verify the contents.

```
$ politeiaverify 39868e5e91c78255-v2.json

Server key : e88df79a4b02699e6c051adbae05f21f2a2f24942e0f27cade165548ec3d6387
Token      : 39868e5e91c78255
Merkle root: 2d00aaa0768701fd011943fbe8ae92f84ee268ca134d6b14f877c3153072bb3c
Signature  : b2a69823f85b62941d845c439726a2504026a0d29fd50ecabe5648b0128328c2fade0ddb354594d48a209dff24e73795ec9cb175d028155cbfa1901114f4b608

Record successfully verified
```

## Manual verification

When verifying manually the user must provide the server public key (`-k`),
the censorship token (`-t`), the censorship record signature (`-s`), and the
file paths for all files that were part of the record.

```
$ politeiaverify \
-k e88df79a4b02699e6c051adbae05f21f2a2f24942e0f27cade165548ec3d6387 \
-t 39868e5e91c78255 \
-s b2a69823f85b62941d845c439726a2504026a0d29fd50ecabe5648b0128328c2fade0ddb354594d48a209dff24e73795ec9cb175d028155cbfa1901114f4b608 \
index.md

Server key : e88df79a4b02699e6c051adbae05f21f2a2f24942e0f27cade165548ec3d6387
Token      : 39868e5e91c78255
Merkle root: 2d00aaa0768701fd011943fbe8ae92f84ee268ca134d6b14f877c3153072bb3c
Signature  : b2a69823f85b62941d845c439726a2504026a0d29fd50ecabe5648b0128328c2fade0ddb354594d48a209dff24e73795ec9cb175d028155cbfa1901114f4b608

Record successfully verified
```
