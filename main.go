// Copyright Key Inside Co., Ltd. 2018 All Rights Reserved.

package main

import (
	"encoding/json"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/protos/peer"
)

var logger = shim.NewLogger("kiesnet-id")

// Chaincode _
type Chaincode struct {
}

// Init implements shim.Chaincode interface.
func (cc *Chaincode) Init(stub shim.ChaincodeStubInterface) peer.Response {
	return shim.Success(nil)
}

// Invoke implements shim.Chaincode interface.
func (cc *Chaincode) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	fn, params := stub.GetFunctionAndParameters()

	switch fn {
	case "get":
		return cc.get(stub)
	case "kid":
		return cc.kid(stub, (len(params) > 0 && params[0] != ""))
	case "list":
		return cc.list(stub, params)
	case "pin":
		return cc.pin(stub)
	case "register":
		return cc.register(stub)
	case "revoke":
		return cc.revoke(stub, params)
	}

	return shim.Error("unknown function: '" + fn + "'")
}

func (cc *Chaincode) get(stub shim.ChaincodeStubInterface) peer.Response {
	invoker, _, err := getInvokerAndIdentityStub(stub, false)
	if err != nil {
		return responseError(err, "failed to get the invoker's identity")
	}
	return responseIdentity(invoker)
}

func (cc *Chaincode) kid(stub shim.ChaincodeStubInterface, secure bool) peer.Response {
	invoker, _, err := getInvokerAndIdentityStub(stub, secure)
	if err != nil {
		return responseError(err, "failed to get the invoker's identity")
	}
	return shim.Success([]byte(invoker.ID))
}

// params[0] : bookmark
func (cc *Chaincode) list(stub shim.ChaincodeStubInterface, params []string) peer.Response {
	invoker, idStub, err := getInvokerAndIdentityStub(stub, false)
	if err != nil {
		return responseError(err, "failed to get the invoker's identity")
	}

	bookmark := ""
	if len(params) > 0 {
		bookmark = params[0]
	}
	res, err := idStub.GetQueryCertificatesResult(invoker.ID, bookmark)
	if err != nil {
		return responseError(err, "failed to get certificate list")
	}

	data, err := json.Marshal(res)
	if err != nil {
		logger.Debug(err.Error())
		return shim.Error("failed to marshal certificate list")
	}
	return shim.Success(data)
}

func (cc *Chaincode) pin(stub shim.ChaincodeStubInterface) peer.Response {
	invoker, idStub, err := getInvokerAndIdentityStub(stub, true)
	if err != nil {
		return responseError(err, "failed to get the invoker's identity")
	}

	if err = idStub.UpdatePIN(invoker.KID()); err != nil {
		return responseError(err, "failed to update the PIN")
	}

	return responseIdentity(invoker)
}

func (cc *Chaincode) register(stub shim.ChaincodeStubInterface) peer.Response {
	idStub, err := NewIdentityStub(stub)
	if err != nil {
		return responseError(err, "failed to get the invoker's identity")
	}

	cert, err := idStub.GetCertificate("")
	if err != nil {
		if _, ok := err.(NotRegisteredCertificateError); !ok {
			return responseError(err, "failed to register the certificate")
		}
	} else if err = cert.Validate(); err != nil { // validate
		return responseError(err, "failed to register the certificate")
	}

	kid, err := idStub.GetKID(true) // check PIN
	if err != nil {
		if _, ok := err.(NotRegisteredCertificateError); !ok {
			return responseError(err, "failed to get the invoker's KID")
		}
		// create new KID
		kid, err = idStub.CreateKID()
		if err != nil {
			return responseError(err, "failed to create new KID")
		}
	}

	if nil == cert { // register the certificate
		cert, err = idStub.CreateCertificate(kid.ID)
		if err != nil {
			return responseError(err, "failed to register the certificate")
		}
	}

	identity := NewIdentity(kid, cert)
	return responseIdentity(identity)
}

// params[0] : Serial Number
func (cc *Chaincode) revoke(stub shim.ChaincodeStubInterface, params []string) peer.Response {
	if len(params) != 1 {
		return shim.Error("incorrect number of parameters. expecting 1")
	}

	_, idStub, err := getInvokerAndIdentityStub(stub, true)
	if err != nil {
		return responseError(err, "failed to get the invoker's identity")
	}

	// ISSUE: have to prevent self-revoking ?
	sn := params[0]
	revokee, err := idStub.GetCertificate(sn)
	if err != nil {
		return responseError(err, "failed to get the certificate to be revoked")
	}
	if revokee.RevokedTime != nil {
		return shim.Error("already revoked certificate")
	}

	if err = idStub.RevokeCertificate(revokee); err != nil {
		return responseError(err, "failed to revoke the certificate")
	}

	data, err := json.Marshal(revokee)
	if err != nil {
		logger.Debug(err.Error())
		return shim.Error("failed to marshal the certificate")
	}
	return shim.Success(data)
}

// returns invoker's Identity and IdentityStub
func getInvokerAndIdentityStub(stub shim.ChaincodeStubInterface, secure bool) (*Identity, *IdentityStub, error) {
	idStub, err := NewIdentityStub(stub)
	if err != nil {
		return nil, nil, err
	}

	identity := &Identity{}

	cert, err := idStub.GetCertificate("")
	if err != nil {
		return nil, idStub, err
	}
	if err = cert.Validate(); err != nil {
		return nil, idStub, err
	}
	identity.SetCertificate(cert)

	kid, err := idStub.GetKID(secure)
	if err != nil {
		return nil, idStub, err
	}
	identity.SetKID(kid)

	return identity, idStub, nil
}

// If 'err' is IdentityError, it will add err's message to the 'msg'.
func responseError(err error, msg string) peer.Response {
	logger.Debug(err.Error())
	if _, ok := err.(IdentityError); ok {
		msg = msg + ": " + err.Error()
	}
	return shim.Error(msg)
}

func responseIdentity(identity *Identity) peer.Response {
	data, err := json.Marshal(identity)
	if err != nil {
		logger.Debug(err.Error())
		return shim.Error("failed to marshal the identity")
	}
	return shim.Success(data)
}

func main() {
	if err := shim.Start(new(Chaincode)); err != nil {
		logger.Criticalf("failed to start chaincode: %s", err)
	}
}
