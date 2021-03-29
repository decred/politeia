// Copyright (c) 2020-2021 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package util

// Argon2Params represent the argon2 key derivation parameters that are used
// to derive various keys in politeia.
type Argon2Params struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"keylen"`
	Salt    []byte `json:"salt"`
}

// NewArgon2Params returns a new Argon2Params with default values.
func NewArgon2Params() Argon2Params {
	salt, err := Random(16)
	if err != nil {
		panic(err)
	}
	return Argon2Params{
		Time:    1,
		Memory:  64 * 1024, // In KiB
		Threads: 4,
		KeyLen:  32,
		Salt:    salt,
	}
}
