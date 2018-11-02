# Kiesnet Identity Chaincode

method __`func`__ arg1 arg2 _arg3_ {trs1, _trs2_}
- method : __query__ or __invoke__
- func : function name
- arg : mandatory argument
- _arg_ : optional argument
- {trs} : mandatory transient
- {_trs_} : optional transient

#

> query __`get`__ {_pin_}
- Get invoker's identity({ kid, sn })
- If {_pin_} is set, PIN validation will be perform. Or not.

> query __`list`__ _bookmark_ {_pin_}
- Get invoker's certificates list
- If {_pin_} is set, PIN validation will be perform. Or not.

> invoke __`pin`__ {pin, new_pin}
- Update the PIN

> invoke __`register`__ {_pin_}
- Register invoker's certificate
- If client user has already PIN, {pin} is manaatory.

> invoke __`revoke`__ serial_number {pin}
- Revoke the certificate
