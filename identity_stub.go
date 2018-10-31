// Copyright Key Inside Co., Ltd. 2018 All Rights Reserved.

package main

import (
	"encoding/hex"
	"encoding/json"

	"github.com/hyperledger/fabric/core/chaincode/lib/cid"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/key-inside/kiesnet-ccpkg/txtime"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"
)

// PageSize _
const PageSize = 20

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

	idStub := &IdentityStub{}
	idStub.stub = stub
	idStub.cid = hex.EncodeToString(h)
	idStub.sn = hex.EncodeToString(cert.SerialNumber.Bytes())
	idStub.transients = transients

	return idStub, nil
}

// GetTransient _
func (idStub *IdentityStub) GetTransient(key string) []byte {
	return idStub.transients[key]
}

// KID

// CreateKIDCompositeKey _
func (idStub *IdentityStub) CreateKIDCompositeKey() (string, error) {
	return idStub.stub.CreateCompositeKey("KID", []string{idStub.cid})
}

// CreateKID creates new KID and writes it into the ledger
func (idStub *IdentityStub) CreateKID() (*KID, error) {
	ts, err := txtime.GetTime(idStub.stub)
	if err != nil {
		return nil, err
	}

	pinCode := string(idStub.GetTransient("pin"))
	pin, err := NewPIN(pinCode)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create the PIN")
	}
	pin.UpdatedTime = ts

	kid := NewKID(idStub.cid + idStub.stub.GetTxID())
	kid.Pin = pin
	kid.CreatedTime = ts

	// TODO: check KID duplication (need indexing)

	if err = idStub.PutKID(kid); err != nil {
		return nil, err
	}
	return kid, nil
}

// GetKID retrieves the KID from the ledger.
// If 'secure' is true, 'pin' must be in transient map.
func (idStub *IdentityStub) GetKID(secure bool) (*KID, error) {
	key, err := idStub.CreateKIDCompositeKey()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create the KID composite key")
	}

	data, err := idStub.stub.GetState(key)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get the KID state")
	}
	if data != nil {
		kid := &KID{}
		if err = json.Unmarshal(data, kid); err != nil {
			return nil, errors.Wrap(err, "failed to unmarshal the KID")
		}

		pinBytes := idStub.GetTransient("pin")
		if pinBytes != nil || secure {
			pinCode := string(pinBytes)
			if kid.Pin != nil {
				if !kid.Pin.Match(pinCode) {
					return nil, MismatchedPINError{}
				}
			} else if pinCode != "" { // non-PIN client
				return nil, MismatchedPINError{}
			}
		}

		return kid, nil
	}
	// no KID = non-registered client
	return nil, NotRegisteredCertificateError{}
}

// PutKID writes the KID into the ledger
func (idStub *IdentityStub) PutKID(kid *KID) error {
	key, err := idStub.CreateKIDCompositeKey()
	if err != nil {
		return errors.Wrap(err, "failed to create the KID composite key")
	}

	data, err := json.Marshal(kid)
	if err != nil {
		return errors.Wrap(err, "failed to marshal the KID")
	}

	err = idStub.stub.PutState(key, data)
	if err != nil {
		return errors.Wrap(err, "failed to put the KID state")
	}
	return nil
}

// UpdatePIN _
func (idStub *IdentityStub) UpdatePIN(kid *KID) error {
	pinBytes := idStub.GetTransient("new_pin")
	pin, err := NewPIN(string(pinBytes))
	if err != nil {
		return errors.Wrap(err, "failed to update the PIN")
	}
	pin.UpdatedTime, err = txtime.GetTime(idStub.stub)
	if err != nil {
		return errors.Wrap(err, "failed to update the PIN")
	}

	kid.Pin = pin
	return idStub.PutKID(kid)
}

// Certificate

// CreateCertificateCompositeKey _
func (idStub *IdentityStub) CreateCertificateCompositeKey(sn string) (string, error) {
	return idStub.stub.CreateCompositeKey("CERT", []string{idStub.cid, sn})
}

// CreateCertificate creates new certificate and writes it into the ledger
func (idStub *IdentityStub) CreateCertificate() (*Certificate, error) {
	ts, err := txtime.GetTime(idStub.stub)
	if err != nil {
		return nil, err
	}

	cert := NewCertificate(idStub.sn)
	cert.CreatedTime = ts

	if err = idStub.PutCertificate(cert); err != nil {
		return nil, err
	}
	return cert, nil
}

// GetCertificate retrieves the certificate from the ledger
func (idStub *IdentityStub) GetCertificate(sn string) (*Certificate, error) {
	if "" == sn {
		sn = idStub.sn
	}
	key, err := idStub.CreateCertificateCompositeKey(sn)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create the certificate composite key")
	}

	data, err := idStub.stub.GetState(key)
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

// QueryCertificates _
func (idStub *IdentityStub) QueryCertificates() (*QueryResult, error) {
	// TODO: indexing, condition (not revoked)
	iter, meta, err := idStub.stub.GetStateByPartialCompositeKeyWithPagination("CERT", []string{idStub.cid}, PageSize, "")
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	return NewQueryResult(meta, iter)
}

// PutCertificate writes the certificate into the ledger
func (idStub *IdentityStub) PutCertificate(cert *Certificate) error {
	key, err := idStub.CreateCertificateCompositeKey(cert.SN)
	if err != nil {
		return errors.Wrap(err, "failed to create the certificate composite key")
	}

	data, err := json.Marshal(cert)
	if err != nil {
		return errors.Wrap(err, "failed to marshal the certificate")
	}

	err = idStub.stub.PutState(key, data)
	if err != nil {
		return errors.Wrap(err, "failed to put the certificate state")
	}
	return nil
}

// RevokeCertificate revokes the certificate and writes it into the ledger
func (idStub *IdentityStub) RevokeCertificate(cert *Certificate) error {
	ts, err := txtime.GetTime(idStub.stub)
	if err != nil {
		return errors.Wrap(err, "failed to revoke the certificate")
	}
	cert.RevokedTime = ts

	err = idStub.PutCertificate(cert)
	if err != nil {
		return errors.Wrap(err, "failed to revoke the certificate")
	}
	return nil
}
