// Copyright Key Inside Co., Ltd. 2018 All Rights Reserved.

package main

// IdentityError is the interface used to distinguish responsible errors
type IdentityError interface {
	IsIdentityError() bool
}

// IdentityErrorImpl _
type IdentityErrorImpl struct{}

// IsIdentityError _
func (e IdentityErrorImpl) IsIdentityError() bool {
	return true
}

// NotRegisteredCertificateError _
type NotRegisteredCertificateError struct {
	IdentityErrorImpl
}

// Error implements error interface
func (e NotRegisteredCertificateError) Error() string {
	return "not registrated certificate"
}

// RevokedCertificateError _
type RevokedCertificateError struct {
	IdentityErrorImpl
}

// Error implements error interface
func (e RevokedCertificateError) Error() string {
	return "revoked certificate"
}

// MismatchedPINError _
type MismatchedPINError struct {
	IdentityErrorImpl
}

// Error implements error interface
func (e MismatchedPINError) Error() string {
	return "mismatched PIN"
}
