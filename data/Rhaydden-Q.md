# QA Report

# [QA-01] Signature count in `verifyECDSA` function may lead to false positive validation 

## Impact
The `verifyECDSA` function may incorrectly return true even when the required number of valid signatures from authorized validators has not been reached. This could allow unauthorized transactions to be validated

## Proof of Concept
Take a look at the [`verifyECDSA`](https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/solidity/handler/contracts/SettlementSignatureVerifier.sol#L133-L136) function:

```solidity
if (
    validators[msgHash.recover(sig)] && ++m >= required_validators
) {
    return true;
}
```

Here, the `++m` operation is performed regardless of whether `validators[msgHash.recover(sig)]` is true or false. This means that every iteration of the loop increments `m`, potentially leading to incorrect results if invalid signatures are encountered.
As a result, if there are enough invalid signatures, the function may incorrectly return `true`, even though the required number of valid signatures from authorized validators has not been reached.

## Recommended Mitigation Steps
Consider incrementing `m` only when a valid signature is encountered

```diff
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
-       if (
-           validators[msgHash.recover(sig)] && ++m >= required_validators
-       ) {
-           return true;
-       }
+       address recoveredAddress = msgHash.recover(sig);
+       if (validators[recoveredAddress]) {
+           m++;
+           if (m >= required_validators) {
+               return true;
+           }
+       }
    }

    return false;
}
```


# [QA-02] Incomplete initialization in `_Settlement_init` function


The `_Settlement_init` function of the `BaseSettlement` contract does not properly initialize all inherited contracts, specifically `AccessControlUpgradeable`. Currently, the function calls `__Ownable_init(_owner)` and `__UUPSUpgradeable_init()`, but it bypasses the standard initializer for `AccessControlUpgradeable`. While this does not pose an immediate risk, it deviates from best practices for using upgradeable contracts.

The [implementation in `BaseSettlement.sol`](https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/solidity/settlement/contracts/BaseSettlement.sol#L53-L74): 

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

    // ... rest of the initialization
}
```

To align with best practices and ensure that all aspects of the contract are correctly initialized, modify the `_Settlement_init` function to include a call to `__AccessControl_init()` alongside the existing initializations of `OwnableUpgradeable` and `UUPSUpgradeable`.


# [QA-03] Incorrect right-shift in `to_bytes32` will cause misalignment of bytes

## Impact
The `to_bytes32` function in the `AddressCast.sol` library incorrectly right-aligns the input bytes when converting a `bytes` array to a `bytes32`. This can cause issues when handling shorter byte arrays, such as Ethereum addresses. The expected behavior is to left-align the bytes, with zero-padding on the right. 

## Proof of Concept

https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/solidity/handler/contracts/libraries/AddressCast.sol#L47-L57

```solidity
function to_bytes32(
    bytes calldata _addressBytes
) internal pure returns (bytes32 result) {
    if (_addressBytes.length > 32) revert AddressCast_InvalidAddress();
    result = bytes32(_addressBytes);
    unchecked {
        uint256 offset = 32 - _addressBytes.length;
        result = result >> (offset * 8);  // Right-shifting causes misalignment
    }
}
```

The function right-shifts the `bytes32` result by `(32 - _addressBytes.length) * 8` bits, which moves the input bytes to the least significant positions (right-aligned). It is expected is to left-align the input bytes (i.e., place them in the most significant positions) and zero-pad the remaining bytes on the right.

For example, if the input is a 20-byte Ethereum address, the current implementation will place the address in the least significant 20 bytes of the `bytes32` result, which is not the expected behavior.

## Recommended Mitigation Steps

Left-shift the result instead of right-shifting ensuring that the input bytes are left-aligned in the `bytes32` result.

```diff
function to_bytes32(
    bytes calldata _addressBytes
) internal pure returns (bytes32 result) {
    if (_addressBytes.length > 32) revert AddressCast_InvalidAddress();
    result = bytes32(_addressBytes);
    unchecked {
-        uint256 offset = 32 - _addressBytes.length;
-        result = result >> (offset * 8);  // Incorrect right-shift
+        uint256 offset = (32 - _addressBytes.length) * 8;
+        result = result << offset;  // Correct left-shift for proper alignment
    }
}
```



# [QA-04] Overly restrictive operator removal prevents status correction

## Impact
The implementation of the `remove_operator` function in the ckrBTC contract prevents managers from removing an address that is not currently an operator. 

## Proof of Concept
Take a look at the `remove_operator` function:
https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/cairo/handler/src/ckr_btc.cairo#L181-L193

```cairo
fn remove_operator(ref self: ContractState, old_operator: ContractAddress) -> bool {
    let caller = get_caller_address();
    assert(self.chakra_managers.read(caller) == 1, Errors::NOT_MANAGER);
    assert(self.chakra_operators.read(old_operator) == 1, Errors::NOT_OPERATOR);
    self.chakra_operators.write(old_operator, 0);
    self
        .emit(
            OperatorRemoved {
                old_operator: old_operator, removed_at: get_block_timestamp()
            }
        );
    return self.chakra_operators.read(old_operator) == 0;
}
```

The function [asserts](https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/cairo/handler/src/ckr_btc.cairo#L183) that the `old_operator` is currently an operator before proceeding with the removal:

```cairo
assert(self.chakra_operators.read(old_operator) == 1, Errors::NOT_OPERATOR);
```

This assertion causes the function to revert if the `old_operator` is not currently an operator, preventing the removal of addresses that are already not operators. 

## Recommended Mitigation Steps
Consider modifying the `remove_operator` function to allow the removal operation regardless of the current operator status. 

```diff
 fn remove_operator(ref self: ContractState, old_operator: ContractAddress) -> bool {
     let caller = get_caller_address();
     assert(self.chakra_managers.read(caller) == 1, Errors::NOT_MANAGER);
-    assert(self.chakra_operators.read(old_operator) == 1, Errors::NOT_OPERATOR);
+    if self.chakra_operators.read(old_operator) == 0 {
+        return true; // Already not an operator
+    }
     self.chakra_operators.write(old_operator, 0);
     self
         .emit(
             OperatorRemoved {
                 old_operator: old_operator, removed_at: get_block_timestamp()
             }
         );
-    return self.chakra_operators.read(old_operator) == 0;
+    return true;
 }
```




# [QA-05] Incorrect chain information in `CrossChainHandleResult` event leads to misrepresentation of cross-chain message flow

## Impact
The `receive_cross_chain_msg` function in the `settlement.cairo` contract emits an event with an incorrect `from_chain` value. 

## Proof of Concept
In the `receive_cross_chain_msg` function, the `to_chain` parameter is [asserted](https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/cairo/handler/src/settlement.cairo#L337) to match the current contract's chain name:

```cairo
assert(to_chain == self.chain_name.read(), 'error to_chain');
```

But, when emitting the `CrossChainHandleResult` event, the `from_chain` field is [incorrectly set](https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/cairo/handler/src/settlement.cairo#L373-L381) to `to_chain`:


```cairo
self.emit(CrossChainHandleResult{
    cross_chain_settlement_id: cross_chain_msg_id,
    from_chain: to_chain,  // Incorrect assignment
    from_handler: to_handler,
    to_chain: from_chain,
    to_handler: from_handler,
    cross_chain_msg_status: status,
    payload_type: payload_type
});
```

This results in the `from_chain` field in the event being incorrectly set to the destination chain (`to_chain`) instead of the current contract's chain name. This could lead to incorrect event data.

## Recommended Mitigation Steps
The `from_chain` field in the `CrossChainHandleResult` event should be set to the current contract's chain name (`self.chain_name.read()`). 

```diff
self.emit(CrossChainHandleResult{
-    from_chain: to_chain,
+    from_chain: self.chain_name.read(),
    from_handler: to_handler,
    to_chain: from_chain,
    to_handler: from_handler,
    cross_chain_msg_status: status,
    payload_type: payload_type
});
```


# [QA-06] Potential reversion in signature verification due to use of `recover()` instead of `tryRecover()`

## Impact
The current implementation of the `verifyECDSA` function in the `SettlementSignatureVerifier` contract may revert unexpectedly when processing invalid signatures. This can cause the entire verification process failing even if there are valid signatures present, disrupting the settlement process. In a multi-signature scenario, this could prevent legitimate transactions from being processed if a single invalid signature is included.

## Proof of Concept
Take a look at the `verifyECDSA` function: https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/solidity/handler/contracts/SettlementSignatureVerifier.sol#L120-L141

```solidity
function verifyECDSA(
    bytes32 msgHash,
    bytes calldata signatures
) internal view returns (bool) {
    // ... (omitted for brevity)
    for (uint256 i = 0; i < len; i += 65) {
        bytes memory sig = signatures[i:i + 65];
        if (
            validators[msgHash.recover(sig)] && ++m >= required_validators
        ) {
            return true;
        }
    }
         return false;
}
```

The `recover()` function is used to retrieve the signer's address from the signature. However, `recover()` will revert if the recovered address is `address(0)`, which occurs with invalid signatures. This means that if any signature in the batch is invalid, the entire verification process will revert, potentially blocking valid transactions.

## Recommended Mitigation Steps
Replace `recover()` with `tryRecover()` in the `verifyECDSA` function. The `tryRecover()` function returns an error code when the retrieved address is `address(0)`, allowing for graceful handling of invalid signatures without reverting the entire process. 



# [QA-07] Loop conditions check in `decode_message` and `decode_transfer` functions causes incorrect parsing of payloads


## Impact
The incorrect loop conditions in `decode_message` and `decode_transfer` allow incorrect parsing of the payload data. Because of this, wrong values will be extracted for the `version`, `message_id`, `payload_type`, `message_payload`, `from`, `to`, `from_token`, `to_token`, and `amount` fields. 

## Proof of Concept
Take look at [`decode_message`](https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/cairo/handler/src/codec.cairo#L29-L43)

```cairo
loop {
    if i <= 0 {
        version = *payload.span().at(i);
    } else if i <= 32 {
        message_id_array.append(*payload.span().at(i));
    } else if i <= 33 {
        payload_type = *payload.span().at(i);
    } else if i <= payload.span().len() - 1 {
        message_payload.append(*payload.span().at(i));
    } else {
        break;
    }
    i += 1;
};
```

The problem here is::
1. The condition `if i <= 0` should be `if i == 0` because the version is only at index `0`.
2. The condition `else if i <= 32` is incorrect because it includes index `0`, which is already used for the `version`. The correct range should be `1 <= i <= 32`.
3. The condition `else if i <= 33` is incorrect because it includes index `32`, which is part of the `message_id_array`. The correct condition should be `else if i == 33`.
4. The condition `else if i <= payload.span().len() - 1` is incorrect because it should be `else if i >= 34 && i <= payload.span().len() - 1` to ensure that the `message_payload` starts from index 34 (after the `payload_type`) and goes until the end of the payload array.

Also check the [`decode_transfer`](https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/cairo/handler/src/codec.cairo#L62-L77)
```cairo
loop {
    if i <= 32 {
        from_payload.append(*payload.span().at(i));
    } else if i <= 64 {
        to_payload.append(*payload.span().at(i));
    } else if i <= 96 {
        from_token_payload.append(*payload.span().at(i));
    } else if i <= 128 {
        to_token_payload.append(*payload.span().at(i));
    } else if i <= 160 {
        amount_payload.append(*payload.span().at(i));
    } else {
        break;
    }
    i += 1;
};
```

Also:
1. The condition `if i <= 32` should be `if i >= 1 && i <= 32` because the first byte (index `0`) is used for the `method_id`.
2. The condition `else if i <= 64` should be `else if i >= 33 && i <= 64`.
3. The condition `else if i <= 96` should be `else if i >= 65 && i <= 96`.
4. The condition `else if i <= 128` should be `else if i >= 97 && i <= 128`.
5. The condition `else if i <= 160` should be `else if i >= 129 && i <= 160`.


## Recommended Mitigation Steps

```diff
pub fn decode_message(payload: Array<u8>) -> Message {
    // ...
    loop {
-       if i <= 0 {
+       if i == 0 {
            version = *payload.span().at(i);
-       } else if i <= 32 {
+       } else if i >= 1 && i <= 32 {
            message_id_array.append(*payload.span().at(i));
-       } else if i <= 33 {
+       } else if i == 33 {
            payload_type = *payload.span().at(i);
-       } else if i <= payload.span().len() - 1 {
+       } else if i >= 34 && i <= payload.span().len() - 1 {
            message_payload.append(*payload.span().at(i));
        } else {
            break;
        }
        i += 1;
    };
    // ...
}

pub fn decode_transfer(payload: Array<u8>) -> ERC20Transfer {
    // ...
    loop {
-       if i <= 32 {
+       if i >= 1 && i <= 32 {
            from_payload.append(*payload.span().at(i));
-       } else if i <= 64 {
+       } else if i >= 33 && i <= 64 {
            to_payload.append(*payload.span().at(i));
-       } else if i <= 96 {
+       } else if i >= 65 && i <= 96 {
            from_token_payload.append(*payload.span().at(i));
-       } else if i <= 128 {
+       } else if i >= 97 && i <= 128 {
            to_token_payload.append(*payload.span().at(i));
-       } else if i <= 160 {
+       } else if i >= 129 && i <= 160 {
            amount_payload.append(*payload.span().at(i));
        } else {
            break;
        }
        i += 1;
    };
    // ...
}
```





# [QA-08] Token burning logic in `MintBurn` mode could lead to potential token loss

## Impact
`MintBurn` mode in the `cross_chain_erc20_settlement` function transfers tokens from the caller to the contract instead of burning them directly. This leads to an incorrect burning of tokens in the `receive_cross_chain_callback` function, potentially resulting in token loss and inconsistencies in the token supply.

## Proof of Concept
In the `cross_chain_erc20_settlement` function, the `MintBurn` mode incorrectly transfers tokens from the caller to the contract instead of burning them:

https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/cairo/handler/src/handler_erc20.cairo#L125-L126

```cairo
if self.mode.read() == SettlementMode::MintBurn{
    token.transfer_from(get_caller_address(), get_contract_address(), amount);
}
```

Then, in the `receive_cross_chain_callback` function, the tokens are burned from the contract:

```cairo
if self.mode.read() == SettlementMode::MintBurn{
    erc20.burn_from(get_contract_address(), self.created_tx.read(cross_chain_msg_id).amount);
}
```

This burning operation in the callback function is flawed because the tokens should have already been burned on the source chain when initiating the transfer in the `cross_chain_erc20_settlement` function. 

## Recommended Mitigation Steps
Consider updating the `cross_chain_erc20_settlement` function to burn the tokens directly on the source chain when initiating the transfer in the `MintBurn` mode, instead of transferring them to the contract. Remove the burning operation from the `receive_cross_chain_callback` function as it would no longer be needed after the suggested change in the `cross_chain_erc20_settlement` function.



# [QA-09] Misspelled enum status / typo in decode 

## Proof of Concept
There are two enums with a misspelled status:
https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/solidity/handler/contracts/BaseSettlementHandler.sol#L24

https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/solidity/handler/contracts/BaseSettlementHandler.sol#L101

```solidity
enum CrossChainTxStatus {
    Unknow,
    Pending,
    Minted,
    Settled,
    Failed
}

enum HandlerStatus {
    Unknow,
    Pending,
    Success,
    Failed
}
```

The first status in both enums is spelled "Unknow" instead of "Unknown". 



Also `deocde_transfer` function has a typo. The function name should be changed to `decode_transfer`
https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/solidity/handler/contracts/ERC20CodecV1.sol#L65

## Recommended Mitigation Steps

Correct the spelling in both cases
