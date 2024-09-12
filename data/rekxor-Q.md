Manager (non-trusted entity) can call `renounceOwnership()` revoking their role and causing DoS on add/remove validator.

Due to the use of AccessControlUpgradeable contracts that provides the onlyRole(role) modifier. It checks that whether the calling entity is the mentioned role.

Also, it has a `renounceOwnership()` that can be called by any manager to self revoke their role, this opens an attack vector, in a scenario wherein single (malicious) manager that has the manager role 
1. He can call `remove_validator() on all the existing validators.
2. Also, can `set_required_validator_num(type(uint256).max)` DoS'ing the `verifyECDSA()` functionality as :
```solidity
    function verifyECDSA(
        bytes32 msgHash,
        bytes calldata signatures
    ) internal view returns (bool) {
        require(
            signatures.length % 65 == 0,
            "Signature length must be a multiple of 65"
        );

        uint256 len = signatures.length;
        uint256 m = 0;
        for (uint256 i = 0; i < len; i += 65) {
            bytes memory sig = signatures[i:i + 65];
           if (
  @>>           validators[msgHash.recover(sig)] && ++m >= required_validators
            ) {
                return true;
            }
        }

        return false;
    }
```
would never return true, due to the huge value of required_validators set by the malicious only remaining manager.
3. He can then call `renounceOwnership()` revoking his Manager role.

The above scenario will lead to temporary DoS of the functionality, until the `owner` grants Manager role to legit addresses which will forever disallow such an attack vector to be available again.