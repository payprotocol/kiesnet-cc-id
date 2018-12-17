// Copyright Key Inside Co., Ltd. 2018 All Rights Reserved.

package main

import (
	"encoding/hex"

	"github.com/key-inside/kiesnet-ccpkg/txtime"
	"golang.org/x/crypto/sha3"
)

// KID _
type KID struct {
	DOCTYPEID   string       `json:"@kid"`
	Pin         *PIN         `json:"pin,omitempty"`
	CreatedTime *txtime.Time `json:"created_time,omitempty"`
}

// NewKID _
func NewKID(cid, nonce string) *KID {
	kid := &KID{}
	kid.DOCTYPEID = kid.CreateHash(cid + nonce)
	return kid
}

// CreateHash _
func (kid *KID) CreateHash(rawID string) string {
	h := make([]byte, 20)
	sha3.ShakeSum256(h, []byte(rawID))
	return hex.EncodeToString(h)
}
