# Kiesnet Identity Chaincode

> [query] __`get`__
- Get the identity
- If transient has PIN, it will validate PIN, or not.

> [query] __`list`__
- Get identities list shares same Kiesnet ID (KID)
- If transient has PIN, it will validate PIN, or not.

> [invoke] __`pin`__
- Update new PIN
- Transient must have 'pin'(current PIN) and 'new_pin'

> [invoke] __`register`__
- Register a identity
- If client user has the KID, transient must have PIN.

> [invoke] __`revoke`__
- Revoke a identity
- Parameter must have a Serial Number.
- Transient must have PIN.
