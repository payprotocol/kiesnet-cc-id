// Copyright Key Inside Co., Ltd. 2018 All Rights Reserved.

package main

import "encoding/json"

// Identity _
type Identity struct {
	kid  *KID
	cert *Certificate
}

// NewIdentity _
func NewIdentity(kid *KID, cert *Certificate) *Identity {
	return &Identity{
		kid:  kid,
		cert: cert,
	}
}

// KID _
func (identity *Identity) KID() *KID {
	return identity.kid
}

// Certificate _
func (identity *Identity) Certificate() *Certificate {
	return identity.cert
}

// GetID _
func (identity *Identity) GetID() string {
	if identity.kid != nil {
		return identity.kid.DOCTYPEID
	}
	return ""
}

// GetSN _
func (identity *Identity) GetSN() string {
	if identity.cert != nil {
		return identity.cert.SN
	}
	return ""
}

// MarshalPayload _
func (identity *Identity) MarshalPayload() ([]byte, error) {
	return json.Marshal(&struct {
		ID string `json:"id"`
		SN string `json:"sn"`
	}{ID: identity.GetID(), SN: identity.GetSN()})
}
