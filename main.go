// Copyright Key Inside Co., Ltd. 2018 All Rights Reserved.

package main

import (
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/protos/peer"
	"github.com/key-inside/kiesnet-ccpkg/txtime"
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
	if txFn := routes[fn]; txFn != nil {
		return txFn(stub, params)
	}
	return shim.Error("unknown function: [" + fn + "]")
}

// TxFunc _
type TxFunc func(shim.ChaincodeStubInterface, []string) peer.Response

// routes is the map of invoke functions
var routes = map[string]TxFunc{
	"get":      txGet,
	"kid":      txKid,
	"list":     txList,
	"lock":     txLock,
	"pin":      txPin,
	"register": txRegister,
	"revoke":   txRevoke,
	"unlock":   txUnlock,
	"ver":      txVer,
}

// tx functions

func txGet(stub shim.ChaincodeStubInterface, params []string) peer.Response {
	invoker, _, err := getInvokerAndIdentityStub(stub, false)
	if err != nil {
		return responseError(err, "failed to get the invoker's identity")
	}
	return response(invoker)
}

func txKid(stub shim.ChaincodeStubInterface, params []string) peer.Response {
	migr := (len(params) > 0 && params[0] != "")
	invoker, _, err := getInvokerAndIdentityStub(stub, migr)
	if err != nil {
		return responseError(err, "failed to get the invoker's identity")
	}
	return shim.Success([]byte(invoker.GetID()))
}

// params[0] : bookmark
func txList(stub shim.ChaincodeStubInterface, params []string) peer.Response {
	invoker, ib, err := getInvokerAndIdentityStub(stub, false)
	if err != nil {
		return responseError(err, "failed to get the invoker's identity")
	}

	bookmark := ""
	if len(params) > 0 {
		bookmark = params[0]
	}
	res, err := ib.GetQueryCertificatesResult(invoker.GetID(), bookmark)
	if err != nil {
		return responseError(err, "failed to get certificate list")
	}

	return response(res)
}

func txLock(stub shim.ChaincodeStubInterface, params []string) peer.Response {
	invoker, ib, err := getInvokerAndIdentityStub(stub, true)
	if err != nil {
		return responseError(err, "failed to get the invoker's identity")
	}

	kid := invoker.KID()
	if kid.isPriv {
		return shim.Error("not supported KID")
	}

	if kid.Lock != "" {
		return shim.Error("already locked with the certificate")
	}

	ts, err := txtime.GetTime(stub)
	if err != nil {
		return responseError(err, "failed to lock with the certificate")
	}

	kid.Lock = ib.sn
	kid.UpdatedTime = ts

	if err = ib.PutKID(kid); err != nil {
		return responseError(err, "failed to lock with the certificate")
	}

	return response(kid)
}

func txPin(stub shim.ChaincodeStubInterface, params []string) peer.Response {
	invoker, ib, err := getInvokerAndIdentityStub(stub, true)
	if err != nil {
		return responseError(err, "failed to get the invoker's identity")
	}

	kid := invoker.KID()
	if !kid.isPriv {	// only old-style supported
		return shim.Error("not supported KID")
	}

	if err = ib.UpdatePIN(kid); err != nil {
		return responseError(err, "failed to update the PIN")
	}

	return response(invoker)
}

func txRegister(stub shim.ChaincodeStubInterface, params []string) peer.Response {
	ib, err := NewIdentityStub(stub)
	if err != nil {
		return responseError(err, "failed to get the invoker's identity")
	}

	kid, err := ib.GetKID(true)
	if err != nil {
		if _, ok := err.(NotRegisteredCertificateError); !ok {
			return responseError(err, "failed to get the invoker's KID")
		}
		// create new KID
		kid, err = ib.CreateKID()
		if err != nil {
			return responseError(err, "failed to create new KID")
		}
	}

	cert, err := ib.GetCertificate(kid.DOCTYPEID, "")
	if err != nil {
		if _, ok := err.(NotRegisteredCertificateError); !ok {
			return responseError(err, "failed to register the certificate")
		}
	} else {
		// ISSUE: re-register revoked certificate
		if err = cert.Validate(); err != nil {
			return responseError(err, "failed to register the certificate")
		}
		return shim.Error("already registered certificate")
	}

	cert, err = ib.CreateCertificate(kid.DOCTYPEID)
	if err != nil {
		return responseError(err, "failed to register the certificate")
	}

	return response(NewIdentity(kid, cert))
}

// params[0] : Serial Number
func txRevoke(stub shim.ChaincodeStubInterface, params []string) peer.Response {
	if len(params) != 1 {
		return shim.Error("incorrect number of parameters. expecting 1")
	}

	invoker, ib, err := getInvokerAndIdentityStub(stub, true)
	if err != nil {
		return responseError(err, "failed to get the invoker's identity")
	}

	// ISSUE: have to prevent self-revoking ?
	sn := params[0]
	revokee, err := ib.GetCertificate(invoker.GetID(), sn)
	if err != nil {
		return responseError(err, "failed to get the certificate to be revoked")
	}
	if revokee.RevokedTime != nil {
		return shim.Error("already revoked certificate")
	}

	if err = ib.RevokeCertificate(revokee); err != nil {
		return responseError(err, "failed to revoke the certificate")
	}

	return response(revokee)
}

func txUnlock(stub shim.ChaincodeStubInterface, params []string) peer.Response {
	invoker, ib, err := getInvokerAndIdentityStub(stub, true)
	if err != nil {
		return responseError(err, "failed to get the invoker's identity")
	}

	kid := invoker.KID()
	if kid.isPriv {
		return shim.Error("not supported KID")
	}

	if kid.Lock != "" {
		ts, err := txtime.GetTime(stub)
		if err != nil {
			return responseError(err, "failed to unlock with the certificate")
		}
		kid.Lock = ""
		kid.UpdatedTime = ts
		if err = ib.PutKID(kid); err != nil {
			return responseError(err, "failed to unlock with the certificate")
		}
	}

	return response(kid)
}

func txVer(stub shim.ChaincodeStubInterface, params []string) peer.Response {
	return shim.Success([]byte("Kiesnet ID v1.3.1 created by Key Inside Co., Ltd."))
}

// helpers

// returns invoker's Identity and IdentityStub
func getInvokerAndIdentityStub(stub shim.ChaincodeStubInterface, migr bool) (*Identity, *IdentityStub, error) {
	ib, err := NewIdentityStub(stub)
	if err != nil {
		return nil, nil, err
	}

	kid, err := ib.GetKID(migr)
	if err != nil {
		return nil, ib, err
	}

	cert, err := ib.GetCertificate(kid.DOCTYPEID, "")
	if err != nil {
		return nil, ib, err
	}
	if err = cert.Validate(); err != nil {
		return nil, ib, err
	}

	return NewIdentity(kid, cert), ib, nil
}

func response(payload Payload) peer.Response {
	data, err := payload.MarshalPayload()
	if err != nil {
		logger.Debug(err.Error())
		return shim.Error("failed to marshal payload")
	}
	return shim.Success(data)
}

// If 'err' is ResponsibleError, it will add err's message to the 'msg'.
func responseError(err error, msg string) peer.Response {
	if nil != err {
		logger.Debug(err.Error())
		if _, ok := err.(ResponsibleError); ok {
			if len(msg) > 0 {
				msg = msg + "|" + err.Error()
			} else {
				msg = err.Error()
			}
		}
	}
	return shim.Error(msg)
}

func main() {
	if err := shim.Start(new(Chaincode)); err != nil {
		logger.Criticalf("failed to start chaincode|%s", err)
	}
}
