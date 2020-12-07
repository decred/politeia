# Politeia Verify

`politeiaverify` is a simple tool that allows anyone to independently verify 
that Politeia has received your proposal/comment and that it is sound. The 
input received in this command is the json bundle downloaded from the GUI.
Files from the gui are downloaded with filename `<token>.json` for proposal
bundles and `<token>-comments.json` for proposal comments bundle. If no flag
is passed in, the tool will try to read the filename and call the corresponding
verify method.

## Usage

`politeiaverify [flags] <path to JSON bundle>`

Flags:
  `-proposal` - verify proposal bundle
  `-comments` - verify comments bundle

Examples:

To verify a proposal bundle

```
politeiaverify -proposal c093b8a808ef68665709995a5a741bd02502b9c6c48a99a4b179fef742ca6b2a.json

Proposal signature:
  Public key: 49912d8dd296ce00a4b6afce4f300481ed5403142740e8b510276dccd1cbaccd
  Signature : a0c1e9d887bd77ddf3b4fd650082ae8bc0f7c09631de7dce1b3147140d1163347768abbf2cecd0196ad5019c40dd2a9a16db482955f5cc30a1b79771ccffa90b
Proposal censorship record signature:
  Merkle root: e905baa3391e446ab89270153f45581640e7cef6e162152fa6e469737699c6bd
  Public key : a70134196c3cdf3f85f8af6abaa38c15feb7bccf5e6d3db6212358363465e502
  Signature  : 0bf4c685102db88c06df12f0980f87bda5e285fcc37be4bef118b138bc5dcdfa3dceaa234eaff2e47f5f16224743d9cf7fe31e3244e67e50b1b7685910362e01

Proposal successfully verified

```

To verify a proposal comments bundle

```
politeiaverify -comments c093b8a808ef68665709995a5a741bd02502b9c6c48a99a4b179fef742ca6b2a-comments.json

Comment ID: 1
  Public key: a70134196c3cdf3f85f8af6abaa38c15feb7bccf5e6d3db6212358363465e502
  Receipt   : fdf466b5511a0ad7304bdb45cb387b7c4ebe720c9d5c3271ec144fee92775de5e6f30482d42375eda99c3b704f37a7f70108d4f201f7c91d6024b9ec5aaa110b
  Signature : c48d643784b5c3645afce7965e7d7d9b44978c22829da30174c51e22eda2849e87d6cd304f7fc2e5bdc5d17ab4b515bc89605b7a814355a44cdfa86d8dc4030e

Comments successfully verified
```

If the bundle is in bad format or if it fails to verify, it will return an error.
