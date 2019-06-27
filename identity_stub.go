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
)

const collectionName = "kid"

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
	cid, _ := clientIndentity.GetID()               // error is always nil

	ib := &IdentityStub{}
	ib.stub = stub
	ib.cid = cid
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
		return nil, errors.Wrap(err, "failed to get the timestamp")
	}

	kid := NewKID(ib.cid, ib.stub.GetTxID())

	// check kid collision
	query := CreateQueryKIDByID(kid.DOCTYPEID)
	iter, err := ib.stub.GetQueryResult(query)
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	if iter.HasNext() {
		return nil, errors.New("KID collided, try again")
	}

	kid.CreatedTime = ts
	kid.UpdatedTime = ts
	if err = ib.PutKID(kid); err != nil {
		return nil, err
	}

	return kid, nil
}

// GetKID retrieves the KID from the ledger.
func (ib *IdentityStub) GetKID(migr bool) (*KID, error) {
	key := ib.CreateKIDKey()
	data, err := ib.stub.GetState(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get the KID state")
	}
	if data != nil {	// exist
		kid := &KID{}
		if err = json.Unmarshal(data, kid); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal the KID")
		}

		if kid.Lock != "" && kid.Lock != ib.sn {
			return nil, NotLockedCertificateError{}
		}

		return kid, nil
	}

	// check OB
	data, err = ib.stub.GetPrivateData(collectionName, key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get the KID state")
	}
	if data != nil {
		kid := &KID{}
		if err = json.Unmarshal(data, kid); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal the KID")
		}

		if migr {
			// migrate OB -> YB
			if err = ib.PutKID(kid); err == nil {
				_ = ib.stub.DelPrivateData(collectionName, key)	// ignore error
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

// Certificate

// CertificatesFetchSize _
const CertificatesFetchSize = 20

// CreateCertificateKey _
func (ib *IdentityStub) CreateCertificateKey(kid string, sn string) string {
	return fmt.Sprintf("CERT_%s_%s", kid, sn)
}

// CreateCertificate creates new certificate and writes it into the ledger
func (ib *IdentityStub) CreateCertificate(kid string) (*Certificate, error) {
	ts, err := txtime.GetTime(ib.stub)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get the timestamp")
	}

	cert := NewCertificate(kid, ib.sn)
	cert.CreatedTime = ts
	if err = ib.PutCertificate(cert); err != nil {
		return nil, err
	}

	return cert, nil
}

// GetCertificate retrieves the certificate from the ledger
func (ib *IdentityStub) GetCertificate(kid string, sn string) (*Certificate, error) {
	if "" == sn {
		sn = ib.sn
	}
	data, err := ib.stub.GetState(ib.CreateCertificateKey(kid, sn))
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
	query := CreateQueryNotRevokedCertificates(kid)
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
	if err = ib.stub.PutState(ib.CreateCertificateKey(cert.DOCTYPEID, cert.SN), data); err != nil {
		return errors.Wrap(err, "failed to put the certificate state")
	}
	return nil
}

// RevokeCertificate revokes the certificate and writes it into the ledger
func (ib *IdentityStub) RevokeCertificate(cert *Certificate) error {
	ts, err := txtime.GetTime(ib.stub)
	if err != nil {
		return errors.Wrap(err, "failed to get the timestamp")
	}
	cert.RevokedTime = ts
	if err = ib.PutCertificate(cert); err != nil {
		return errors.Wrap(err, "failed to revoke the certificate")
	}
	return nil
}
