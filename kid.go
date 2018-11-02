// Copyright Key Inside Co., Ltd. 2018 All Rights Reserved.

package main

import (
	"encoding/hex"
	"time"

	"golang.org/x/crypto/sha3"
)

// KID _
type KID struct {
	DOCTYPEID   string     `json:"@kid"` // value is CID
	ID          string     `json:"id"`
	Pin         *PIN       `json:"pin,omitempty"`
	CreatedTime *time.Time `json:"created_time,omitempty"`
}

// NewKID _
func NewKID(rawID string) *KID {
	kid := &KID{}
	kid.ID = kid.CreateHash(rawID)
	return kid
}

// CreateHash _
func (kid *KID) CreateHash(rawID string) string {
	h := make([]byte, 32)
	sha3.ShakeSum256(h, []byte(rawID))
	return hex.EncodeToString(h)
}
