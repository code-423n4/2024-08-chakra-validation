## [L-1] Managers can add as many validators as they want, validators should not exceeds required validators

### Description: 
In `BaseSettlement::add_validators` and `SettlementSignatureVerifier::add_validator` function, Managers can add as many validators they want and this number exceeds `required_validators`. What if Manager add a validator which is not scan/call transactions and this is not intended functionality of the protocol.

### Impact: 
A malicious validator cause denial of service to chakra network.

### Recommended Mitigation:** 
Apply check for validators not exceeding `required_validators`.

## [L-2] Missing zero value check for `required_validators`.

### Description:** 
In `BaseSettlement.sol` `set_required_validators_num` and `SettlementSignatureVerifier::set_required_validators_num` functions allows manager to accidently or maliciously set `required_validators` to zero.

### Impact:** 
If `required_validators` gets zero than no validators are there to make chakra network functional. According to protocol `required_validators` are validators required to function chakra network.

### Recommended Mitigation:** 
Avoid state change if passed parameter is zero.

## [L-3] Missing events while changeing critical state variables.

### Description:** 
In `ChakraSettlementHandler` while `add_handler` and `remove_handler` functions should emit event so that it can be acknowledged that any handler is added or removed.

Also functions initializes like `_Settlement_init` should emit events

### Impact:** 
State variable changes should emit events else there can be issues like loss of funds or anything.

### Recommended Mitigation:** 
State changes should emit events