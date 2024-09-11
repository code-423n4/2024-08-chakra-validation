## [L-01] The `set_required_validators_num(...)` function should validate that the `_required_validators` is not greater than the `validator_count`.

The set_required_validators_num(...) function of SettlementSignatureVerifier.sol contract is used to set a new `required_validators` but there is no check to ensure that the new value is within reasonable range.

If the `required_validators` is greater than the `validator_count` verification will revert.

```solidity
File: SettlementSignatureVerifier.sol
function set_required_validators_num(
        uint256 _required_validators
    ) external virtual onlyRole(MANAGER_ROLE) {
        uint256 old = required_validators;
        required_validators = _required_validators;
        emit RequiredValidatorsChanged(msg.sender, old, required_validators);
    }
```

Instances: 2
- https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/SettlementSignatureVerifier.sol#L92C5-L98C6
- https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/SettlementSignatureVerifier.sol#L139C5-L146C1


#### Recommendation
Consider implementing a validation to ensure that the `_required_validators` is not greater than the `validator_count` this way:

```diff
function set_required_validators_num(
        uint256 _required_validators
    ) external virtual onlyRole(MANAGER_ROLE) {
++      require(_required_validators <= validator_count, "Out of range")
        uint256 old = required_validators;
        required_validators = _required_validators;
        emit RequiredValidatorsChanged(msg.sender, old, required_validators);
    }

```




## [L-02] Attacker can take over implementation contracts because _disableInitializer is not called in the constructors.

The implementation contracts are not protected from being initialized. This allows anyone to gain control of the implementation contracts by initializing them with addresses addresses and go on to perform malicious activities on the logic contract.

9 instances found:
- settlement/contracts/ChakraSettlement.sol
- settlement/contracts/SettlementSignatureVerifier.sol
- settlement/contracts/ChakraSettlementUpgradeTest.sol
- handler/contracts/ChakraSettlementHandler.sol
- handler/contracts/TokenRoles.sol
- handler/contracts/ChakraToken.sol
- handler/contracts/ChakraTokenUpgradeTest.sol
- handler/contracts/ERC20CodecV1.sol
- handler/contracts/SettlementSignatureVerifier



#### Recommendation
Consider disabling the initializer on the implementation contracts this way:

```solidity
[CAUTION]
 * ====
 * Avoid leaving a contract uninitialized.
 *
 * An uninitialized contract can be taken over by an attacker. This applies to both a proxy and its implementation
 * contract, which may impact the proxy. To prevent the implementation contract from being used, you should invoke
 * the {_disableInitializers} function in the constructor to automatically lock it when it is deployed:
 *
 * 
 * 
 * /// @custom:oz-upgrades-unsafe-allow constructor
 * constructor() {
 *     _disableInitializers();
 * }
```