# Kiesnet Identity Chaincode

## API

method __`func`__ [arg1, _arg2_, ... ] {trs1, _trs2_, ... }
- method : __query__ or __invoke__
- func : function name
- [arg] : mandatory argument
- [_arg_] : optional argument
- {trs} : mandatory transient
- {_trs_} : optional transient

#

> query __`get`__
- Get invoker's identity { kid, sn }

> query __`kid`__
- Get invoker's KID

> query __`list`__ [_bookmark_]
- Get invoker's certificates list

> invoke __`lock`__
- Lock the identity with the invoker's certificate

> invoke __`register`__
- Register invoker's certificate

> invoke __`revoke`__ [serial_number]
- Revoke the certificate

> invoke __`unlock`__
- Unlock the identity with the invoker's certificate
- The invoker's certificate must be the certificate which was used to lock the identity.

> query __`ver`__
- Get version
