### Inefficient Gas Usage Due to Lack of Pre-check in `add_handler` and `remove_handler` Functions

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
