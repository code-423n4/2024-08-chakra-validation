## [L-1] Attacker can take over implementation contracts because _disableInitializer is not called in the constructors.

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