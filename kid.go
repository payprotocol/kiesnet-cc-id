// Copyright Key Inside Co., Ltd. 2018 All Rights Reserved.

package main

import (
	"encoding/hex"
	"time"

	"golang.org/x/crypto/sha3"
)

// KID _
type KID struct {
	ID          string     `json:"id"`
	Pin         *PIN       `json:"pin,omitempty"`
	CreatedTime *time.Time `json:"created_time,omitempty"`
}

// CreateHash _
func (kid *KID) CreateHash(id string) string {
	h := make([]byte, 32)
	sha3.ShakeSum256(h, []byte(id))
	return hex.EncodeToString(h)
}

// NewKID _
func NewKID(id string) *KID {
	kid := &KID{}
	kid.ID = kid.CreateHash(id)
	return kid
}
