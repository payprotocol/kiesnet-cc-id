// Copyright Key Inside Co., Ltd. 2018 All Rights Reserved.

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"

	"github.com/key-inside/kiesnet-ccpkg/txtime"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

// PIN _
type PIN struct {
	Hash        string       `json:"hash"`
	Salt        string       `json:"salt"`
	UpdatedTime *txtime.Time `json:"updated_time,omitempty"`
}

// NewPIN _
func NewPIN(code string) (*PIN, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate random salt")
	}

	pin := &PIN{}
	pin.Salt = base64.RawURLEncoding.EncodeToString(salt)
	pin.Hash = pin.CreateHash(code)

	return pin, nil
}

// CreateHash _
func (pin *PIN) CreateHash(code string) string {
	h := make([]byte, 32)
	sha3.ShakeSum256(h, []byte(pin.Salt+"|"+code))
	return hex.EncodeToString(h)
}

// Match _
func (pin *PIN) Match(code string) bool {
	return (pin.CreateHash(code) == pin.Hash)
}