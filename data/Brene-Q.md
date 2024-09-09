## Impact
The `TokenRoles` contract inherits from `UUPSUpgradeable`, which is essential for implementing upgradeable functionality in the proxy pattern. However, the contract does not initialize the `UUPSUpgradeable` component. Without properly initializing this component, the contract is vulnerable to upgrade failures, and the upgradeability of the contract may not function as intended. Additionally, without `_authorizeUpgrade()`, any future upgrades may become insecure or impossible, leading to potential governance or operational issues. The absence of proper initialization of the UUPS mechanism can cause; inability to upgrade the contract when necessary, potential risks for unauthorized upgrades if access control is improperly handled or breakage of the upgradeable pattern if the proxy cannot identify the logic contract.

## Proof of Concept
This [`TokenRoles`](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/TokenRoles.sol#L1-L44) contract does not call `__UUPSUpgradeable_init()` or implement the required `_authorizeUpgrade()` function. 

## Tools Used
Manual Review

## Recommended Mitigation Steps
To ensure proper initialization of the UUPS upgradeable contract and secure the upgrade process, the following changes should be made:
Call `__UUPSUpgradeable_init()` during the contract's initialization process.
Implement the `_authorizeUpgrade()` function to restrict the upgrade capability to authorized entities (e.g., the owner or admin).
```diff
function __TokenRoles_init(address _owner, address _operator) public {
    __Ownable_init(_owner);
+   __UUPSUpgradeable_init();  // Initialize UUPSUpgradeable
    _grantRole(DEFAULT_ADMIN_ROLE, _owner);
    _grantRole(OPERATOR_ROLE, _operator);
}

    /**
     * @dev Function to authorize an upgrade
     * @param newImplementation Address of the new implementation
     */
+   function _authorizeUpgrade(
+       address newImplementation
+   ) internal override onlyOwner {}

```