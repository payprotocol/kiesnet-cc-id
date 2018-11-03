// Copyright Key Inside Co., Ltd. 2018 All Rights Reserved.

package main

import (
	"encoding/hex"
	"time"

	"golang.org/x/crypto/sha3"
)

// KID _
type KID struct {
	DOCTYPEID   string     `json:"@kid"`
	ID          string     `json:"id"`
	Pin         *PIN       `json:"pin,omitempty"`
	CreatedTime *time.Time `json:"created_time,omitempty"`
}

// NewKID _
func NewKID(cid string, nonce string) *KID {
	kid := &KID{}
	kid.DOCTYPEID = cid
	kid.ID = kid.CreateHash(cid + nonce)
	return kid
}

// CreateHash _
func (kid *KID) CreateHash(rawID string) string {
	h := make([]byte, 32)
	sha3.ShakeSum256(h, []byte(rawID))
	return hex.EncodeToString(h)
}
