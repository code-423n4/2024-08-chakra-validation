# `BaseSettlementHandler` Contract Inherits `AccessControlUpgradeable` But Never Uses It

## Explanation
The `BaseSettlementHandler` contract inherits from `AccessControlUpgradeable`, which provides role-based access control features. However, the contract does not use any methods provided by `AccessControlUpgradeable`, nor does it grant the `DEFAULT_ADMIN_ROLE` to any address. This unnecessary inheritance increases the contract's bytecode size, making it more complex and potentially more expensive to deploy and interact with. Moreover, the lack of granted roles could lead to confusion or improper security assumptions about access control in the contract.
