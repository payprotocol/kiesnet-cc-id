// Copyright Key Inside Co., Ltd. 2018 All Rights Reserved.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric/core/chaincode/lib/cid"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/key-inside/kiesnet-ccpkg/txtime"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

// IdentityStub _
type IdentityStub struct {
	stub       shim.ChaincodeStubInterface
	cid        string // client id
	sn         string // serial number
	transients map[string][]byte
}

// NewIdentityStub _
func NewIdentityStub(stub shim.ChaincodeStubInterface) (*IdentityStub, error) {
	transients, err := stub.GetTransient()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get transients")
	}

	clientIndentity, err := cid.New(stub)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get the client identity")
	}

	cert, _ := clientIndentity.GetX509Certificate() // error is always nil
	id, _ := clientIndentity.GetID()                // error is always nil
	h := make([]byte, 32)                           // id hash bytes
	sha3.ShakeSum256(h, []byte(id))

	ib := &IdentityStub{}
	ib.stub = stub
	ib.cid = hex.EncodeToString(h)
	ib.sn = hex.EncodeToString(cert.SerialNumber.Bytes())
	ib.transients = transients

	return ib, nil
}

// GetTransient _
func (ib *IdentityStub) GetTransient(key string) []byte {
	return ib.transients[key]
}

// KID

// CreateKIDKey _
func (ib *IdentityStub) CreateKIDKey() string {
	return "KID_" + ib.cid
}

// CreateKID creates new KID and writes it into the ledger
func (ib *IdentityStub) CreateKID() (*KID, error) {
	ts, err := txtime.GetTime(ib.stub)
	if err != nil {
		return nil, err
	}

	pinCode := string(ib.GetTransient("kiesnet-id/pin"))
	pin, err := NewPIN(pinCode)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create the PIN")
	}
	pin.UpdatedTime = ts

	kid := NewKID(ib.cid, ib.stub.GetTxID())

	// check kid duplication
	query := fmt.Sprintf(QueryKIDByID, kid)
	iter, err := ib.stub.GetQueryResult(query)
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	if iter.HasNext() {
		return nil, errors.New("oops! duplicated KID")
	}

	kid.Pin = pin
	kid.CreatedTime = ts
	if err = ib.PutKID(kid); err != nil {
		return nil, err
	}

	return kid, nil
}

// GetKID retrieves the KID from the ledger.
// If 'secure' is true, 'pin' must be in transient map.
func (ib *IdentityStub) GetKID(secure bool) (*KID, error) {
	data, err := ib.stub.GetState(ib.CreateKIDKey())
	if err != nil {
		return nil, errors.Wrap(err, "failed to get the KID state")
	}
	if data != nil {
		kid := &KID{}
		if err = json.Unmarshal(data, kid); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal the KID")
		}

		pinBytes := ib.GetTransient("kiesnet-id/pin")
		if pinBytes != nil || secure {
			if kid.Pin != nil { // never be false
				if !kid.Pin.Match(string(pinBytes)) {
					return nil, MismatchedPINError{}
				}
			}
		}

		return kid, nil
	}
	// no KID = non-registered client
	return nil, NotRegisteredCertificateError{}
}

// PutKID writes the KID into the ledger
func (ib *IdentityStub) PutKID(kid *KID) error {
	data, err := json.Marshal(kid)
	if err != nil {
		return errors.Wrap(err, "failed to marshal the KID")
	}
	if err = ib.stub.PutState(ib.CreateKIDKey(), data); err != nil {
		return errors.Wrap(err, "failed to put the KID state")
	}
	return nil
}

// UpdatePIN _
func (ib *IdentityStub) UpdatePIN(kid *KID) error {
	pinBytes := ib.GetTransient("kiesnet-id/new_pin")
	pin, err := NewPIN(string(pinBytes))
	if err != nil {
		return errors.Wrap(err, "failed to update the PIN")
	}
	pin.UpdatedTime, err = txtime.GetTime(ib.stub)
	if err != nil {
		return errors.Wrap(err, "failed to update the PIN")
	}

	kid.Pin = pin
	return ib.PutKID(kid)
}

// Certificate

// CertificatesFetchSize _
const CertificatesFetchSize = 20

// CreateCertificateKey _
func (ib *IdentityStub) CreateCertificateKey(sn string) string {
	return fmt.Sprintf("CERT_%s_%s", ib.cid, sn)
}

// CreateCertificate creates new certificate and writes it into the ledger
func (ib *IdentityStub) CreateCertificate(kid string) (*Certificate, error) {
	ts, err := txtime.GetTime(ib.stub)
	if err != nil {
		return nil, err
	}

	cert := NewCertificate(kid, ib.sn)
	cert.CreatedTime = ts
	if err = ib.PutCertificate(cert); err != nil {
		return nil, err
	}

	return cert, nil
}

// GetCertificate retrieves the certificate from the ledger
func (ib *IdentityStub) GetCertificate(sn string) (*Certificate, error) {
	if "" == sn {
		sn = ib.sn
	}
	data, err := ib.stub.GetState(ib.CreateCertificateKey(sn))
	if err != nil {
		return nil, errors.Wrap(err, "failed to get the certificate state")
	}
	if data != nil {
		cert := &Certificate{}
		if err = json.Unmarshal(data, cert); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal the certificate")
		}
		return cert, nil
	}
	return nil, NotRegisteredCertificateError{}
}

// GetQueryCertificatesResult _
func (ib *IdentityStub) GetQueryCertificatesResult(kid, bookmark string) (*QueryResult, error) {
	query := fmt.Sprintf(QueryNotRevokedCertificates, kid)
	iter, meta, err := ib.stub.GetQueryResultWithPagination(query, CertificatesFetchSize, bookmark)
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	return NewQueryResult(meta, iter)
}

// PutCertificate writes the certificate into the ledger
func (ib *IdentityStub) PutCertificate(cert *Certificate) error {
	data, err := json.Marshal(cert)
	if err != nil {
		return errors.Wrap(err, "failed to marshal the certificate")
	}
	if err = ib.stub.PutState(ib.CreateCertificateKey(cert.SN), data); err != nil {
		return errors.Wrap(err, "failed to put the certificate state")
	}
	return nil
}

// RevokeCertificate revokes the certificate and writes it into the ledger
func (ib *IdentityStub) RevokeCertificate(cert *Certificate) error {
	ts, err := txtime.GetTime(ib.stub)
	if err != nil {
		return errors.Wrap(err, "failed to revoke the certificate")
	}
	cert.RevokedTime = ts
	if err = ib.PutCertificate(cert); err != nil {
		return errors.Wrap(err, "failed to revoke the certificate")
	}
	return nil
}
