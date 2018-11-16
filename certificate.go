// Copyright Key Inside Co., Ltd. 2018 All Rights Reserved.

package main

import (
	"encoding/json"
	"time"
)

// Certificate _
type Certificate struct {
	DOCTYPEID   string     `json:"@certificate"`
	SN          string     `json:"sn"`
	CreatedTime *time.Time `json:"created_time,omitempty"`
	RevokedTime *time.Time `json:"revoked_time,omitempty"`
}

// NewCertificate _
func NewCertificate(kid, sn string) *Certificate {
	return &Certificate{
		DOCTYPEID: kid,
		SN:        sn,
	}
}

// Validate _
func (cert *Certificate) Validate() error {
	if cert.RevokedTime != nil {
		return RevokedCertificateError{}
	}
	return nil
}

// MarshalPayload _
func (cert *Certificate) MarshalPayload() ([]byte, error) {
	return json.Marshal(cert)
}
