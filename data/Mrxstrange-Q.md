# 1. Redundant Payload Type Checks in Solidity Function

**Function:** ChakraSettlementHandler.sol#L300 → `receive_cross_chain_msg`

**Issue:**

The function `receive_cross_chain_msg` contains redundant checks for the `payload_type` parameter. Specifically:

1. The `require` statement verifies the validity of `payload_type` through the `isValidPayloadType` function.
2. A second check (`if (payload_type == PayloadType.ERC20)`) is performed later in the function, although `isValidPayloadType` already restricts the payload type to `PayloadType.ERC20`.

**Code Fragment:**  ChakraSettlementHandler.sol#L316-L318

```solidity

require(isValidPayloadType(payload_type), "Invalid payload type");

if (payload_type == PayloadType.ERC20) {
    // Additional logic for PayloadType.ERC20
}

```

**Redundant Check:**
The function `isValidPayloadType` only validates `PayloadType.ERC20`, as shown below:

```solidity
function isValidPayloadType(PayloadType payload_type) internal pure returns (bool) {
    return (payload_type == PayloadType.ERC20);
}
```

This makes the subsequent check for `PayloadType.ERC20` redundant, causing unnecessary duplication in the code.