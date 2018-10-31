// Copyright Key Inside Co., Ltd. 2018 All Rights Reserved.

package main

// Identity _
type Identity struct {
	ID string `json:"id"`
	SN string `json:"sn"`

	kid  *KID
	cert *Certificate
}

// NewIdentity _
func NewIdentity(kid *KID, cert *Certificate) *Identity {
	identity := &Identity{}
	identity.SetKID(kid)
	identity.SetCertificate(cert)
	return identity
}

// KID _
func (identity *Identity) KID() *KID {
	return identity.kid
}

// Certificate _
func (identity *Identity) Certificate() *Certificate {
	return identity.cert
}

// SetKID _
func (identity *Identity) SetKID(kid *KID) {
	identity.kid = kid
	identity.ID = kid.ID
}

// SetCertificate _
func (identity *Identity) SetCertificate(cert *Certificate) {
	identity.cert = cert
	identity.SN = cert.SN
}
