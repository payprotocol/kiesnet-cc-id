# Kiesnet Identity Chaincode

method __`func`__ arg1 arg2 _arg3_ {trs1, _trs2_}
- method : __query__ or __invoke__
- func : function name
- arg : mandatory argument
- _arg_ : optional argument
- {trs} : mandatory transient
- {_trs_} : optional transient

#

> query __`get`__ _type_ {_"kiesnet-id/pin"_}
- Get invoker's identity
- _type_ : "text" or "json", default "json"
    - "text" : only KID
    - "json" : { kid, sn }
- If {_"kiesnet-id/pin"_} is set, PIN validation will be perform. Or not.

> query __`list`__ _bookmark_ {_"kiesnet-id/pin"_}
- Get invoker's certificates list
- If {_"kiesnet-id/pin"_} is set, PIN validation will be perform. Or not.

> invoke __`pin`__ {"kiesnet-id/pin", "kiesnet-id/new_pin"}
- Update the PIN

> invoke __`register`__ {_"kiesnet-id/pin"_}
- Register invoker's certificate
- If client user has already PIN, {"kiesnet-id/pin"} is manaatory.

> invoke __`revoke`__ serial_number {"kiesnet-id/pin"}
- Revoke the certificate
