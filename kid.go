// Copyright Key Inside Co., Ltd. 2018 All Rights Reserved.

package main

import (
	"encoding/hex"
	"encoding/json"

	"github.com/key-inside/kiesnet-ccpkg/txtime"
	"golang.org/x/crypto/sha3"
)

// KID _
type KID struct {
	DOCTYPEID   string       `json:"@kid"`
	Lock		string       `json:"lock,omitempty"`
	Pin         *PIN         `json:"pin,omitempty"`
	CreatedTime *txtime.Time `json:"created_time,omitempty"`
	UpdatedTime *txtime.Time `json:"updated_time,omitempty"`
	isPriv		bool
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

// MarshalPayload _
func (kid *KID) MarshalPayload() ([]byte, error) {
	if kid.isPriv {
		_kid := &KID{
			DOCTYPEID: kid.DOCTYPEID,
			Lock: "",	// not support
			Pin: nil,	// remove pin
			CreatedTime: kid.CreatedTime,
			UpdatedTime: kid.UpdatedTime,
		}
		return json.Marshal(_kid)
	}

	return json.Marshal(kid)
}