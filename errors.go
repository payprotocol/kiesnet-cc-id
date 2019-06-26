// Copyright Key Inside Co., Ltd. 2018 All Rights Reserved.

package main

// ResponsibleError is the interface used to distinguish responsible errors
type ResponsibleError interface {
	IsReponsible() bool
}

// ResponsibleErrorImpl _
type ResponsibleErrorImpl struct{}

// IsReponsible _
func (e ResponsibleErrorImpl) IsReponsible() bool {
	return true
}

// NotRegisteredCertificateError _
type NotRegisteredCertificateError struct {
	ResponsibleErrorImpl
}

// Error implements error interface
func (e NotRegisteredCertificateError) Error() string {
	return "not registrated certificate"
}

// RevokedCertificateError _
type RevokedCertificateError struct {
	ResponsibleErrorImpl
}

// Error implements error interface
func (e RevokedCertificateError) Error() string {
	return "revoked certificate"
}

// MismatchedPINError _
type MismatchedPINError struct {
	ResponsibleErrorImpl
}

// Error implements error interface
func (e MismatchedPINError) Error() string {
	return "mismatched PIN"
}

// NotLockedCertificateError _
type NotLockedCertificateError struct {
	ResponsibleErrorImpl
}

// Error implements error interface
func (e NotLockedCertificateError) Error() string {
	return "not locked certificate"
}
