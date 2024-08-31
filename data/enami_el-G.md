### G-01 Inefficient Gas Usage Due to Lack of Pre-check in `add_handler` and `remove_handler` Functions

### Description:
The current implementation of the `add_handler` and `remove_handler` functions does not include a check to verify the current status of the `handler_whitelist` before updating it. This can lead to unnecessary state changes, consuming more gas than required. By adding a pre-check to ensure that the handler is not already in the desired state, gas usage can be optimized, reducing costs for users interacting with these functions.

### Part of Code:
```solidity
function add_handler(
    string memory chain_name,
    uint256 handler
) external onlyOwner {
    handler_whitelist[chain_name][handler] = true;
}

/**
 * @dev Removes a handler from the whitelist for a given chain
 * @param chain_name The name of the chain
 * @param handler The handler address to remove
 */
function remove_handler(
    string memory chain_name,
    uint256 handler
) external onlyOwner {
    handler_whitelist[chain_name][handler] = false;
}
```


### Recommendation:
Add a check before updating the `handler_whitelist` to verify if the handler is already in the desired state. This will prevent unnecessary writes to the blockchain, saving gas. The updated functions could look like this:

```solidity
function add_handler(
    string memory chain_name,
    uint256 handler
) external onlyOwner {
    if (!handler_whitelist[chain_name][handler]) {
        handler_whitelist[chain_name][handler] = true;
    }
}

/**
 * @dev Removes a handler from the whitelist for a given chain
 * @param chain_name The name of the chain
 * @param handler The handler address to remove
 */
function remove_handler(
    string memory chain_name,
    uint256 handler
) external onlyOwner {
    if (handler_whitelist[chain_name][handler]) {
        handler_whitelist[chain_name][handler] = false;
    }
}
```
https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/ChakraSettlementHandler.sol#L53-L70



### G-02 Potential Gas Inefficiency Due to Lack of Manager Limit in `_Settlement_init` Function

### Description:
The `_Settlement_init` function currently allows an unlimited number of managers to be assigned. This can lead to significant gas consumption, especially when a large number of managers are added. Since the `_grantRole` function is called in a loop for each manager, the gas cost increases linearly with the number of managers. Without a limit on the number of managers, this could result in excessive gas usage during contract initialization.

### Part of Code:
```solidity
function _Settlement_init(
    string memory _chain_name,
    uint256 _chain_id,
    address _owner,
    address[] memory _managers,
    uint256 _required_validators,
    address _signature_verifier
) public {
    __Ownable_init(_owner);
    __UUPSUpgradeable_init();
    _grantRole(DEFAULT_ADMIN_ROLE, _owner);

    for (uint256 i = 0; i < _managers.length; i++) {
        _grantRole(MANAGER_ROLE, _managers[i]);
    }

    chain_id = _chain_id;
    contract_chain_name = _chain_name;
    required_validators = _required_validators;
    signature_verifier = ISettlementSignatureVerifier(_signature_verifier);
}
```
https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/BaseSettlement.sol#L55-L74

### Recommendation:
To mitigate the potential gas inefficiency, implement a limit on the number of managers that can be assigned during initialization. This can be achieved by adding a `require` statement to enforce a maximum number of managers, which would prevent the loop from iterating excessively.



### G-03 Potential Redundant Role Assignment in `add_manager` Function

### Description:
The `add_manager` function currently assigns the `MANAGER_ROLE` to the provided `_manager` address without checking if the address already holds this role. This can lead to unnecessary gas consumption by redundantly calling `grantRole` for addresses that are already managers. Although this does not impact the functionality of the contract, it can be optimized to prevent unnecessary operations.

### Part of Code:
```solidity
function add_manager(address _manager) external onlyOwner {
    grantRole(MANAGER_ROLE, _manager);
    emit ManagerAdded(msg.sender, _manager);
}
```

### Recommendation:
Before granting the `MANAGER_ROLE`, add a check to see if the `_manager` address already has the role. This will prevent redundant role assignments and save gas.

Example update:
```solidity
function add_manager(address _manager) external onlyOwner {
    if (!hasRole(MANAGER_ROLE, _manager)) {
        grantRole(MANAGER_ROLE, _manager);
        emit ManagerAdded(msg.sender, _manager);
    }
}
```

