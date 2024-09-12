# QA Report: Chakra

## L-01: Race Condition in Cross-Chain Message Processing

### Summary
The `receive_cross_chain_msg` function in the ChakraSettlement contract is responsible for handling incoming cross-chain messages. It verifies signatures, processes messages, and updates transaction statuses. However, there's a critical flaw in its implementation that could lead to race conditions.

The function checks the status of a transaction and then processes it, but these operations are not atomic. This creates a window of vulnerability where multiple calls with the same transaction ID could potentially be processed concurrently.

### Code Snippet

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/ChakraSettlement.sol#L200

```solidity
require(
    receive_cross_txs[txid].status == CrossChainMsgStatus.Unknow,
    "Invalid transaction status"
);

receive_cross_txs[txid] = ReceivedCrossChainTx(
    txid,
    from_chain,
    contract_chain_name,
    from_address,
    from_handler,
    address(this),
    payload,
    CrossChainMsgStatus.Pending
);

bool result = ISettlementHandler(to_handler).receive_cross_chain_msg(
    // ... parameters ...
);
```

### Impact
1. Double processing: The same transaction could be processed multiple times if concurrent calls are made.
2. Inconsistent state: The contract's state could become inconsistent if multiple processes update the same transaction simultaneously.
3. Potential fund loss: In financial applications, this could lead to double-spending or other financial discrepancies.

### Scenario
1. Two nodes on the network receive the same cross-chain message simultaneously.
2. Both nodes call `receive_cross_chain_msg` with the same `txid`.
3. Both calls pass the initial status check (status is Unknown).
4. Both calls proceed to process the message and update the status.
5. The message is processed twice, potentially leading to duplicate actions or inconsistent state.

## Fix
Implement a check-effects-interactions pattern and use a mutex-like mechanism to prevent concurrent processing of the same transaction.

```solidity
function receive_cross_chain_msg(
    uint256 txid,
    // ... other parameters ...
) external {
    require(
        receive_cross_txs[txid].status == CrossChainMsgStatus.Unknow,
        "Invalid transaction status"
    );
   
    // Immediately set status to Pending to prevent concurrent processing
    receive_cross_txs[txid].status = CrossChainMsgStatus.Pending;
   
    // Verify signature
    bytes32 message_hash = keccak256(
        abi.encodePacked(
            txid,
            from_chain,
            from_address,
            from_handler,
            to_handler,
            keccak256(payload)
        )
    );
    require(
        signature_verifier.verify(message_hash, signatures, sign_type),
        "Invalid signature"
    );
   
    // Update other fields of receive_cross_txs[txid]
    receive_cross_txs[txid].from_chain = from_chain;
    receive_cross_txs[txid].to_chain = contract_chain_name;
    // ... set other fields ...
   
    // Process the message
    bool result = ISettlementHandler(to_handler).receive_cross_chain_msg(
        // ... parameters ...
    );
   
    // Update final status
    receive_cross_txs[txid].status = result ? CrossChainMsgStatus.Success : CrossChainMsgStatus.Failed;
   
    emit CrossChainHandleResult(
        // ... parameters ...
    );
}
```

## L-02: Insufficient handling of settlement modes

### Summary

The `receive_cross_chain_msg()` function does not properly handle all the possible settlement modes. Specifically, it doesn't have a case for the "LockMint" settlement mode.

In the `receive_cross_chain_msg()` function, the contract checks the settlement mode and performs the appropriate token operations. However, the function is missing a case for the "LockMint" settlement mode. This could lead to issues if the contract is configured to use the "LockMint" mode, as the incoming cross-chain message would not be processed correctly.

### Code Snippet

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L318

```solidity
if (payload_type == PayloadType.ERC20) {
    // Cross chain transfer
    {
        // Decode transfer payload
        ERC20TransferPayload memory transfer_payload = codec
            .deocde_transfer(msg_payload);

        if (mode == SettlementMode.MintBurn) {
            _erc20_mint(
                AddressCast.to_address(transfer_payload.to),
                transfer_payload.amount
            );
            return true;
        } else if (mode == SettlementMode.LockUnlock) {
            _erc20_unlock(
                AddressCast.to_address(transfer_payload.to),
                transfer_payload.amount
            );
            return true;
        } else if (mode == SettlementMode.LockMint) {
            // Missing case for LockMint mode
            return true;
        } else if (mode == SettlementMode.BurnUnlock) {
            _erc20_unlock(
                AddressCast.to_address(transfer_payload.to),
                transfer_payload.amount
            );
            return true;
        }
    }
}
```

### Impact
If the contract is configured to use the "LockMint" settlement mode, any incoming cross-chain messages would not be processed correctly, leading to a failed transfer or potentially other unexpected behavior.

### Scenario
Imagine a user initiates a cross-chain ERC20 token transfer to the contract, and the contract is configured to use the "LockMint" settlement mode. When the cross-chain message is received, the `receive_cross_chain_msg()` function would not handle the "LockMint" case, and the transfer would likely fail, leaving the user's tokens locked in the contract.

### Fix
To fix this issue, the `receive_cross_chain_msg()` function should include a case for the "LockMint" settlement mode, similar to the other cases:

```solidity
if (payload_type == PayloadType.ERC20) {
    // Cross chain transfer
    {
        // Decode transfer payload
        ERC20TransferPayload memory transfer_payload = codec
            .deocde_transfer(msg_payload);

        if (mode == SettlementMode.MintBurn) {
            _erc20_mint(
                AddressCast.to_address(transfer_payload.to),
                transfer_payload.amount
            );
            return true;
        } else if (mode == SettlementMode.LockUnlock) {
            _erc20_unlock(
                AddressCast.to_address(transfer_payload.to),
                transfer_payload.amount
            );
            return true;
        } else if (mode == SettlementMode.LockMint) {
            _erc20_mint(
                AddressCast.to_address(transfer_payload.to),
                transfer_payload.amount
            );
            return true;
        } else if (mode == SettlementMode.BurnUnlock) {
            _erc20_unlock(
                AddressCast.to_address(transfer_payload.to),
                transfer_payload.amount
            );
            return true;
        }
    }
}
```

## L-03: Incorrect Encoding of Address Types in `encode_transfer` Function

### Summary
The `ERC20CodecV1` contract's `encode_transfer` function is meant to encode ERC20 transfer details into a byte array. However, it's not correctly handling the encoding of address types.

### Details
1. The function is using `abi.encodePacked()` to encode all values, including addresses.
2. Addresses in Solidity are typically 20 bytes long, but when encoded as uint256 (which is what `abi.encodePacked()` does for addresses), they become 32 bytes, potentially leading to data misinterpretation.

### Code Snippet

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ERC20CodecV1.sol#L36

```solidity
function encode_transfer(
    ERC20TransferPayload memory _payload
) external pure returns (bytes memory encodedPaylaod) {
    encodedPaylaod = abi.encodePacked(
        _payload.method_id,
        _payload.from,
        _payload.to,
        _payload.from_token,
        _payload.to_token,
        _payload.amount
    );
}
```

### Impact
1. The encoded payload will be longer than necessary, wasting gas and storage.
2. When decoding, if the receiver expects 20-byte addresses, it will misinterpret the data, potentially leading to incorrect transfers or token assignments.
3. This could result in funds being sent to wrong addresses or lost entirely.

### Scenario
A system using this codec to transfer tokens across chains could send tokens to an incorrect address due to the extra padding added to the address encoding.

### Fix
Use `abi.encode()` for proper type handling, or explicitly cast addresses to `uint160` before encoding:

```solidity
function encode_transfer(
    ERC20TransferPayload memory _payload
) external pure returns (bytes memory encodedPayload) {
    encodedPayload = abi.encode(
        _payload.method_id,
        uint160(_payload.from),
        uint160(_payload.to),
        uint160(_payload.from_token),
        uint160(_payload.to_token),
        _payload.amount
    );
}
```

## L-04: Incorrect Payload Decoding in ERC20CodecV1 Contract

### Summary
The `deocde_transfer` function incorrectly decodes the payload, leading to misalignment of data and potential misinterpretation of transfer details.

### Code Snippet

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ERC20CodecV1.sol#L65

```solidity
function deocde_transfer(
    bytes calldata _payload
) external pure returns (ERC20TransferPayload memory transferPayload) {
    transferPayload.method_id = ERC20Method(uint8(_payload[0]));
    transferPayload.from = abi.decode(_payload[1:33], (uint256));
    transferPayload.to = abi.decode(_payload[33:65], (uint256));
    transferPayload.from_token = abi.decode(_payload[65:97], (uint256));
    transferPayload.to_token = abi.decode(_payload[97:129], (uint256));
    transferPayload.amount = abi.decode(_payload[129:161], (uint256));
}
```

### Impact
1. Incorrect decoding of transfer payloads, leading to wrong addresses, token IDs, and amounts being processed.
2. Potential loss of funds or misdirected transfers in cross-chain or layer-2 operations.
3. Compromised integrity of the entire transfer system relying on this codec.

### Scenario
When a transfer payload is submitted for decoding, the function will extract data from incorrect byte ranges, causing all fields except `method_id` to be incorrectly populated.

### Fix
Correct the byte ranges in the decoding process to properly align with the encoded data:

```solidity
function decode_transfer(
    bytes calldata _payload
) external pure returns (ERC20TransferPayload memory transferPayload) {
    require(_payload.length == 161, "Invalid payload length");
    transferPayload.method_id = ERC20Method(uint8(_payload[0]));
    transferPayload.from = abi.decode(_payload[1:33], (uint256));
    transferPayload.to = abi.decode(_payload[33:65], (uint256));
    transferPayload.from_token = abi.decode(_payload[65:97], (uint256));
    transferPayload.to_token = abi.decode(_payload[97:129], (uint256));
    transferPayload.amount = abi.decode(_payload[129:161], (uint256));
    require(transferPayload.method_id == ERC20Method.Transfer, "Invalid method ID");
}
```

## L-05: Encoding-Decoding Mismatch in ERC20CodecV1 Contract

### Summary
The ERC20CodecV1 contract provides `encode_transfer` and `deocde_transfer` functions for handling ERC20 transfer payloads. These functions should be complementary, but there's a critical mismatch.

The `encode_transfer` function uses `abi.encodePacked`, while the `deocde_transfer` function uses `abi.decode`. This mismatch leads to incorrect decoding of the payload.

### Code Snippets

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ERC20CodecV1.sol#L36

Encoding:
```solidity
function encode_transfer(
    ERC20TransferPayload memory _payload
) external pure returns (bytes memory encodedPaylaod) {
    encodedPaylaod = abi.encodePacked(
        *payload.method*id,
        _payload.from,
        _payload.to,
        *payload.from*token,
        *payload.to*token,
        _payload.amount
    );
}
```

Decoding:
```solidity
function deocde_transfer(
    bytes calldata _payload
) external pure returns (ERC20TransferPayload memory transferPayload) {
    transferPayload.method_id = ERC20Method(uint8(_payload[0]));
    transferPayload.from = abi.decode(_payload[1:33], (uint256));
    transferPayload.to = abi.decode(_payload[33:65], (uint256));
    transferPayload.from_token = abi.decode(_payload[65:97], (uint256));
    transferPayload.to_token = abi.decode(_payload[97:129], (uint256));
    transferPayload.amount = abi.decode(_payload[129:161], (uint256));
}
```

### Impact
1. The decoding function will fail or produce incorrect results when trying to decode payloads created by the encoding function.
2. This could lead to failed transfers, incorrect transfer amounts, or wrong address interpretations in a production environment.

### Scenario
When a payload is encoded using `abi.encodePacked` and then attempts to be decoded using `abi.decode`, the decoding will fail or produce unexpected results due to the different encoding methods.

### Fix
Align the encoding and decoding methods. Either:

1. Change the encoding to use `abi.encode`:
```solidity
function encode_transfer(
    ERC20TransferPayload memory _payload
) external pure returns (bytes memory encodedPayload) {
    encodedPayload = abi.encode(
        _payload.method_id,
        _payload.from,
        _payload.to,
        _payload.from_token,
        _payload.to_token,
        _payload.amount
    );
}
```

Or 

2. Change the decoding to manually extract packed data:
```solidity
function decode_transfer(
    bytes calldata _payload
) external pure returns (ERC20TransferPayload memory transferPayload) {
    require(_payload.length == 161, "Invalid payload length");
    transferPayload.method_id = ERC20Method(uint8(_payload[0]));
    transferPayload.from = uint256(bytes32(_payload[1:33]));
    transferPayload.to = uint256(bytes32(_payload[33:65]));
    transferPayload.from_token = uint256(bytes32(_payload[65:97]));
    transferPayload.to_token = uint256(bytes32(_payload[97:129]));
    transferPayload.amount = uint256(bytes32(_payload[129:161]));
}
```

## L-06: Insufficient chain name validation

### Summary
The `_chain` parameter is assigned to the `chain` state variable without any validation. 

### Code

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/BaseSettlementHandler.sol#L118

```solidity
function _Settlement_handler_init(
        address _owner,
        SettlementMode _mode,
        address _token,
        address _verifier,
        string memory _chain,
        address _settlement
    ) public {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();
        settlement = ISettlement(_settlement);
        verifier = ISettlementSignatureVerifier(_verifier);
        mode = _mode;
        token = _token;
        chain = _chain;
    }
```

### Impact
This can lead to several potential issues:

1. Empty string: The function allows an empty string to be set as the chain name.
2. Overly long strings: There's no limit on the length of the chain name, which could lead to excessive gas costs or potential DoS attacks.
3. Invalid characters: The function doesn't check for invalid or malicious characters in the chain name.


### Fix
Add input validation for the `_chain` parameter:

```solidity
function _Settlement_handler_init(
    address _owner,
    SettlementMode _mode,
    address _token,
    address _verifier,
    string memory _chain,
    address _settlement
) public {
    __Ownable_init(_owner);
    __UUPSUpgradeable_init();
    settlement = ISettlement(_settlement);
    verifier = ISettlementSignatureVerifier(_verifier);
    mode = _mode;
    token = _token;
   
    // Input validation for _chain
    require(bytes(_chain).length > 0, "Chain name cannot be empty");
    require(bytes(_chain).length <= 32, "Chain name too long");
   
    // Optional: Add a check for valid characters if needed
    // require(_isValidChainName(_chain), "Invalid chain name");
   
    chain = _chain;
}

// Optional: Function to check for valid characters in the chain name
function _isValidChainName(string memory _name) private pure returns (bool) {
    bytes memory nameBytes = bytes(_name);
    for (uint i = 0; i < nameBytes.length; i++) {
        byte char = nameBytes[i];
        if (!(char >= 0x30 && char <= 0x39) && // 0-9
            !(char >= 0x41 && char <= 0x5A) && // A-Z
            !(char >= 0x61 && char <= 0x7A) && // a-z
            char != 0x2D && char != 0x5F) { // hyphen and underscore
            return false;
        }
    }
    return true;
}
```

## L-07: Potential Data Integrity Issue in `payload_hash` Function

### Summary
The `payload_hash` function is intended to compute a hash of the payload portion of a message, which could be used for integrity verification or as a unique identifier.

The `payload_hash` function may not correctly handle messages with payloads shorter than expected, potentially leading to hash collisions or incorrect integrity checks.

The `payload_hash` function relies on the `payload` function to extract the payload portion of the message. However, the `payload` function doesn't perform any length checks.

### Code Snippet

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/libraries/MessageV1Codec.sol#L67

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/libraries/MessageV1Codec.sol#L73

```solidity
function payload(bytes calldata _msg) internal pure returns (bytes calldata) {
    return bytes(_msg[PAYLOAD_OFFSET:]);
}
```

If a message is shorter than `PAYLOAD_OFFSET` (34 bytes), this function will return an empty byte array instead of reverting. The `payload_hash` function will then compute a hash of this empty array, which could lead to false positives in integrity checks or collisions in identification systems.

### Impact
1. Data Integrity: Malformed or truncated messages could pass integrity checks based on the payload hash.
2. Security: In systems using this hash for authentication or verification, an attacker could potentially craft messages that produce the same hash as valid messages.
3. Identification: If the hash is used as an identifier, multiple distinct (but malformed) messages could produce the same identifier.

### Scenario
Consider two messages:
1. A properly formatted message with a short payload
2. A truncated message that's shorter than `PAYLOAD_OFFSET`

Both of these could produce the same payload hash, even though one is valid and the other is not.

### Fix
Implement a length check in the `payload` function:

```solidity
function payload(bytes calldata _msg) internal pure returns (bytes calldata) {
    require(_msg.length >= PAYLOAD_OFFSET, "Message too short");
    return bytes(_msg[PAYLOAD_OFFSET:]);
}
```

This ensures that only properly formatted messages can have their payload hashed.

## L-08: Insufficient Handler Validation in ChakraSettlementHandler

### Summary
The ChakraSettlementHandler contract is designed to facilitate cross-chain ERC20 token transfers. It uses a system of whitelisted handlers to validate cross-chain messages. However, there's a critical flaw in how these handlers are validated.

The contract fails to properly validate the `to_handler` when initiating a cross-chain transaction in the `cross_chain_erc20_settlement` function. While the contract checks the validity of incoming handlers, it does not verify if the destination handler is whitelisted before sending tokens.

### Details
In the `cross_chain_erc20_settlement` function:

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L111

```solidity
function cross_chain_erc20_settlement(
    string memory to_chain,
    uint256 to_handler,
    uint256 to_token,
    uint256 to,
    uint256 amount
) external {
    // ... other checks ...
    require(to_handler != 0, "Invalid to handler address");
    // ... rest of the function ...
}
```

The function only checks if `to_handler` is not zero, but doesn't verify if it's a whitelisted handler for the destination chain.

### Impact
This vulnerability could allow an attacker to:
1. Initiate transfers to unauthorized handlers on other chains.
2. Potentially lock or lose tokens by sending them to invalid destinations.
3. Bypass intended security measures of the cross-chain system.

### Scenario
An attacker could exploit this by:
1. Calling `cross_chain_erc20_settlement` with a valid `to_chain` but an unauthorized `to_handler`.
2. The contract would process the transaction, locking or burning tokens on the source chain.
3. The cross-chain message would be sent to an invalid handler on the destination chain, potentially resulting in lost tokens.

### Fix
Implement a check in the `cross_chain_erc20_settlement` function to validate the destination handler:

```solidity
function cross_chain_erc20_settlement(
    string memory to_chain,
    uint256 to_handler,
    uint256 to_token,
    uint256 to,
    uint256 amount
) external {
    require(amount > 0, "Amount must be greater than 0");
    require(to != 0, "Invalid to address");
    require(to_handler != 0, "Invalid to handler address");
    require(to_token != 0, "Invalid to token address");
    require(is_valid_handler(to_chain, to_handler), "Invalid destination handler");

    // ... rest of the function ...
}
```

## L-09: Incorrect Endianness in AddressCast.to_bytes() Function Leads to Reversed Byte Order

### Summary
The `to_bytes` function in the AddressCast library is designed to convert a `bytes32` value to a `bytes` array of a specified size. This function is crucial for operations involving Ethereum addresses and other fixed-size data types that need to be processed or transmitted in different formats.

The `to_bytes` function incorrectly handles the endianness of the input `bytes32` value. The function assumes that the least significant bytes of the input should be placed at the end of the output `bytes` array, which is incorrect for most use cases involving Ethereum addresses.

### Details
1. The function uses a left shift (`shl`) operation in assembly, which moves the most significant bytes of the input to the beginning of the output array.
2. This approach results in the bytes being in reverse order compared to what's typically expected when working with Ethereum addresses.

### Code Snippet

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/libraries/AddressCast.sol#L32

```solidity
function to_bytes(
    bytes32 _addressBytes32,
    uint256 _size
) internal pure returns (bytes memory result) {
    if (_size == 0 || _size > 32)
        revert AddressCast_InvalidSizeForAddress();
    result = new bytes(_size);
    unchecked {
        uint256 offset = 256 - _size * 8;
        assembly {
            mstore(add(result, 32), shl(offset, _addressBytes32))
        }
    }
}
```

### Impact
1. Incorrect byte order: The resulting `bytes` array will have its bytes in reverse order, potentially causing issues when used with other systems or contracts expecting standard Ethereum address representation.
2. Inconsistency with Ethereum standards: This implementation doesn't align with the standard way Ethereum handles address byte order.
3. Potential security risks: If used for address manipulation, it could lead to incorrect address interpretations, possibly resulting in funds being sent to wrong addresses.

### Scenario
Consider converting an Ethereum address to bytes:
```solidity
address addr = 0x742d35Cc6634C0532925a3b844Bc454e4438f44e;
bytes32 addrBytes32 = AddressCast.to_bytes32(addr);
bytes memory result = AddressCast.to_bytes(addrBytes32, 20);
```
The `result` will contain the address bytes in reverse order, which is incorrect for most Ethereum-related operations.

### Fix
To correct this issue, we need to modify the function to preserve the original byte order:

```solidity
function to_bytes(
    bytes32 _addressBytes32,
    uint256 _size
) internal pure returns (bytes memory result) {
    if (_size == 0 || _size > 32)
        revert AddressCast_InvalidSizeForAddress();
    result = new bytes(_size);
    assembly {
        mstore(add(result, 32), _addressBytes32)
    }
}
```

This implementation simply copies the least significant bytes of the input `bytes32` to the output `bytes` array, preserving the original order.

## L-10: Incorrect Byte Alignment in `to_bytes32` Function

### Summary
The `to_bytes32` function is intended to convert a `bytes` array to a `bytes32` value, aligning the bytes to the right.

The current implementation of the `to_bytes32` function incorrectly aligns the input bytes, potentially leading to data corruption or misinterpretation of addresses.

### Code Snippet

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/libraries/AddressCast.sol#L47

```solidity
function to_bytes32(
    bytes calldata _addressBytes
) internal pure returns (bytes32 result) {
    if (_addressBytes.length > 32) revert AddressCast_InvalidAddress();
    result = bytes32(_addressBytes);
    unchecked {
        uint256 offset = 32 - _addressBytes.length;
        result = result >> (offset * 8);
    }
}
```

The function first casts the input to `bytes32`, which left-aligns the data (padding with zeros on the right). It then attempts to right-align by shifting right, but this operation loses the significant bits instead of preserving them.

### Impact
This bug can lead to:
1. Incorrect conversion of addresses or other byte data.
2. Potential security vulnerabilities if address data is misinterpreted.
3. Inconsistencies in data representation across the contract ecosystem.

### Scenario
Consider an input of a 20-byte Ethereum address:
```
Input: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
```
Expected output (right-aligned in bytes32):
```
0x000000000000000000000000742d35Cc6634C0532925a3b844Bc454e4438f44e
```
Actual output (with the current implementation):
```
0x0000000000000000000000000000000000000000000000000000000000000000
```

### Fix
Modify the function to properly right-align the input bytes:

```solidity
function to_bytes32(
    bytes calldata _addressBytes
) internal pure returns (bytes32 result) {
    if (_addressBytes.length > 32) revert AddressCast_InvalidAddress();
    assembly {
        result := 0
        let length := _addressBytes.length
        let src := add(_addressBytes.offset, 32)
        let dst := add(result, 32)
        dst := sub(dst, length)
        mstore(result, mload(src))
    }
}
```

This implementation uses inline assembly to:
1. Initialize `result` to zero.
2. Calculate the correct memory positions for source and destination.
3. Copy the input bytes to the right-aligned position in the `result`.


## L-11: Lack of Pausability in Critical Functions

### Summary
The `SettlementSignatureVerifier` contract contains critical functions that, if compromised, could lead to significant security risks. These functions lack a pause mechanism, which is crucial for emergency situations or during upgrades.

The contract's critical functions, such as `add_validator`, `remove_validator`, and `verify`, can be called at any time, even in situations where it might be necessary to halt the contract's operations temporarily.

### Code Snippet

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/SettlementSignatureVerifier.sol#L76

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/SettlementSignatureVerifier.sol#L113

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/SettlementSignatureVerifier.sol#L174

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/SettlementSignatureVerifier.sol#L108


```solidity
function add_validator(address validator) external onlyRole(MANAGER_ROLE) {
    require(validators[validator] == false, "Validator already exists");
    validators[validator] = true;
    validator_count += 1;
    emit ValidatorAdded(msg.sender, validator);
}

function verify(bytes32 msgHash, bytes calldata signatures, uint8 sign_type) external view returns (bool) {
    if (sign_type == 0) {
        return verifyECDSA(msgHash, signatures);
    } else {
        return false;
    }
}
```

### Impact
Without a pause mechanism, the contract remains vulnerable during critical periods such as upgrades or when a security breach is detected. This could lead to unauthorized additions or removals of validators, or allow potentially malicious transactions to be verified during compromised periods.

### Scenario
If a vulnerability is discovered in the contract or in one of the validator's systems, there's no way to quickly halt operations while the issue is being addressed. Malicious actors could exploit this window of vulnerability to add unauthorized validators or push through fraudulent transactions.

### Fix
Implement the `PausableUpgradeable` contract from OpenZeppelin and add pause functionality to critical functions.

1. Import the `PausableUpgradeable` contract:
```solidity
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
```

2. Inherit from `PausableUpgradeable` and initialize it:
```solidity
contract SettlementSignatureVerifier is
    OwnableUpgradeable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable
{
    function initialize(address _owner, uint256 _required_validators) public initializer {
        // ... existing initializations
        __Pausable_init();
    }
}
```

3. Add `whenNotPaused` modifier to critical functions:
```solidity
function add_validator(address validator) external onlyRole(MANAGER_ROLE) whenNotPaused {
    require(validators[validator] == false, "Validator already exists");
    validators[validator] = true;
    validator_count += 1;
    emit ValidatorAdded(msg.sender, validator);
}

function verify(bytes32 msgHash, bytes calldata signatures, uint8 sign_type) external view whenNotPaused returns (bool) {
    if (sign_type == 0) {
        return verifyECDSA(msgHash, signatures);
    } else {
        return false;
    }
}
```

4. Add pause and unpause functions:
```solidity
function pause() external onlyOwner {
    _pause();
}

function unpause() external onlyOwner {
    _unpause();
}
```

These changes will allow the contract owner to pause critical functions in case of emergencies, providing an additional layer of security and control over the contract's operations.


## L-12: Lack of Structured Data Signing Support

### Summary
The `SettlementSignatureVerifier` contract currently uses basic ECDSA signatures for verification. While this is functional, it doesn't support more advanced structured data signing methods, which can provide additional security and clarity in the signing process.

### Details
The contract uses the ECDSA library for signature verification, but it doesn't implement EIP-712, a standard for typed structured data hashing and signing. EIP-712 provides a more secure and user-friendly way of signing data, as it allows users to see a human-readable version of what they're signing.

### Code Snippet

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/SettlementSignatureVerifier.sol#L108

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/SettlementSignatureVerifier.sol#L120

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/SettlementSignatureVerifier.sol#L174

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/SettlementSignatureVerifier.sol#L193

```solidity
function verifyECDSA(bytes32 msgHash, bytes calldata signatures) internal view returns (bool) {
    require(signatures.length % 65 == 0, "Signature length must be a multiple of 65");

    uint256 len = signatures.length;
    uint256 m = 0;
    for (uint256 i = 0; i < len; i += 65) {
        bytes memory sig = signatures[i:i + 65];
        if (validators[msgHash.recover(sig)] && ++m >= required_validators) {
            return true;
        }
    }

    return false;
}
```

### Impact
Without support for structured data signing:
1. Users may sign data without fully understanding what they're agreeing to, as the signed message is just a hash.
2. The contract misses out on the enhanced security features provided by EIP-712.
3. It's harder to integrate with wallets and dapps that prefer EIP-712 for a better user experience.

### Scenario
A user is asked to sign a transaction, but because the data is hashed, they can't easily verify what they're signing. This could lead to users inadvertently signing malicious transactions.

### Fix
Implement EIP-712 support using OpenZeppelin's `EIP712Upgradeable` contract.

1. Import the `EIP712Upgradeable` contract:
```solidity
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
```

2. Inherit from `EIP712Upgradeable` and initialize it:
```solidity
contract SettlementSignatureVerifier is
    OwnableUpgradeable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    EIP712Upgradeable
{
    function initialize(address _owner, uint256 _required_validators) public initializer {
        // ... existing initializations
        __EIP712_init("SettlementSignatureVerifier", "1");
    }
}
```

3. Add a function to verify EIP-712 signatures:
```solidity
function verifyTypedDataV4(bytes32 digest, bytes memory signature) public view returns (bool) {
    address signer = ECDSA.recover(digest, signature);
    return validators[signer];
}
```

4. Update the `verify` function to support EIP-712 signatures:
```solidity
function verify(bytes32 msgHash, bytes calldata signatures, uint8 sign_type) external view whenNotPaused returns (bool) {
    if (sign_type == 0) {
        return verifyECDSA(msgHash, signatures);
    } else if (sign_type == 1) {
        return verifyTypedDataV4(msgHash, signatures);
    } else {
        return false;
    }
}
```

These changes will allow the contract to support both traditional ECDSA signatures and EIP-712 structured data signatures, providing more flexibility and security in the signature verification process. Users will be able to see and verify the exact data they're signing, reducing the risk of signing malicious transactions.


## L-13: Inefficient Validator Management

### Summary
The `SettlementSignatureVerifier` contract currently uses a simple mapping and a counter to manage validators. This approach lacks efficiency in certain operations and doesn't provide easy enumeration of validators.

The contract uses a `mapping(address => bool)` to store validators and a separate `validator_count` variable. This structure makes it difficult to efficiently iterate over all validators or retrieve a list of all current validators. Additionally, the current implementation doesn't provide a way to check if the maximum number of validators has been reached.

### Code Snippet

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/SettlementSignatureVerifier.sol#L43

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/SettlementSignatureVerifier.sol#L39

```solidity
mapping(address => bool) public validators;
uint256 public validator_count;

function add_validator(address validator) external onlyRole(MANAGER_ROLE) {
    require(validators[validator] == false, "Validator already exists");
    validators[validator] = true;
    validator_count += 1;
    emit ValidatorAdded(msg.sender, validator);
}

function remove_validator(address validator) external onlyRole(MANAGER_ROLE) {
    require(validators[validator] == true, "Validator does not exists");
    validators[validator] = false;
    validator_count -= 1;
    emit ValidatorRemoved(msg.sender, validator);
}
```

### Impact
1. Inefficient enumeration: It's not possible to efficiently list all current validators.
2. Potential inconsistencies: The `validator_count` could become out of sync with the actual number of validators if not managed carefully.
3. Lack of upper bound: There's no built-in way to limit the total number of validators.
4. Gas inefficiency: Operations like checking all validators or removing all validators would be gas-intensive.

### Scenario
If the contract needs to perform an operation involving all validators (e.g., a periodic review or reset), it would be extremely inefficient or practically impossible with the current structure.

### Fix
Implement OpenZeppelin's `EnumerableSetUpgradeable` to manage validators more efficiently.

1. Import the `EnumerableSetUpgradeable` contract:
```solidity
import {EnumerableSetUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/structs/EnumerableSetUpgradeable.sol";
```

2. Replace the current validator storage with an `EnumerableSet`:
```solidity
using EnumerableSetUpgradeable for EnumerableSetUpgradeable.AddressSet;
EnumerableSetUpgradeable.AddressSet private _validators;
```

3. Update the `add_validator` and `remove_validator` functions:
```solidity
function add_validator(address validator) external onlyRole(MANAGER_ROLE) whenNotPaused {
    require(_validators.add(validator), "Validator already exists");
    emit ValidatorAdded(msg.sender, validator);
}

function remove_validator(address validator) external onlyRole(MANAGER_ROLE) whenNotPaused {
    require(_validators.remove(validator), "Validator does not exist");
    emit ValidatorRemoved(msg.sender, validator);
}
```

4. Add functions to get validator information:
```solidity
function getValidatorCount() public view returns (uint256) {
    return _validators.length();
}

function getValidatorAtIndex(uint256 index) public view returns (address) {
    return _validators.at(index);
}

function is_validator(address _validator) external view returns (bool) {
    return _validators.contains(_validator);
}
```

5. Update the `verifyECDSA` function to use the new structure:
```solidity
function verifyECDSA(bytes32 msgHash, bytes calldata signatures) internal view returns (bool) {
    require(signatures.length % 65 == 0, "Signature length must be a multiple of 65");

    uint256 len = signatures.length;
    uint256 m = 0;
    for (uint256 i = 0; i < len; i += 65) {
        bytes memory sig = signatures[i:i + 65];
        if (_validators.contains(msgHash.recover(sig)) && ++m >= required_validators) {
            return true;
        }
    }

    return false;
}
```

## L-14: Unbounded Payload Size in ChakraSettlement Contract

### Summary
The `send_cross_chain_msg` function accepts a `bytes calldata payload` parameter without any size limit. This unbounded payload size can lead to potential Denial of Service (DoS) attacks and excessive gas consumption.

### Code Snippet

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/ChakraSettlement.sol#L116

```solidity
function send_cross_chain_msg(
    string memory to_chain,
    address from_address,
    uint256 to_handler,
    PayloadType payload_type,
    bytes calldata payload
) external {
    nonce_manager[from_address] += 1;

    address from_handler = msg.sender;

    uint256 txid = uint256(
        keccak256(
            abi.encodePacked(
                contract_chain_name, // from chain
                to_chain,
                from_address, // msg.sender address
                from_handler, // settlement handler address
                to_handler,
                nonce_manager[from_address]
            )
        )
    );

    create_cross_txs[txid] = CreatedCrossChainTx(
        txid,
        contract_chain_name,
        to_chain,
        from_address,
        from_handler,
        to_handler,
        payload,
        CrossChainMsgStatus.Pending
    );

    emit CrossChainMsg(
        txid,
        from_address,
        contract_chain_name,
        to_chain,
        from_handler,
        to_handler,
        payload_type,
        payload
    );
}
```

### Impact
1. **DoS Attack**: An attacker could send transactions with extremely large payloads, consuming a significant amount of gas and potentially exceeding the block gas limit. This could prevent other transactions from being included in the block.
2. **Excessive Gas Consumption**: Even if the transaction doesn't exceed the block gas limit, it could still consume an unnecessarily large amount of gas, making the function prohibitively expensive to call.
3. **Storage Bloat**: Large payloads are stored in the contract's storage (in `create_cross_txs`), which could lead to blockchain bloat and increased costs for nodes maintaining the blockchain state.

### Scenario
1. An attacker identifies the unbounded payload vulnerability.
2. They craft a transaction calling `send_cross_chain_msg` with a payload just small enough to fit within the block gas limit.
3. This transaction consumes nearly all available gas in a block, preventing other transactions from being included.
4. If repeated, this could significantly disrupt the normal operation of the contract and the blockchain.

### Fix
Implement a maximum payload size limit:

```solidity
// Add this constant at the contract level
uint256 private constant MAX_PAYLOAD_SIZE = 1024; // Example size, adjust as needed

function send_cross_chain_msg(
    string memory to_chain,
    address from_address,
    uint256 to_handler,
    PayloadType payload_type,
    bytes calldata payload
) external {
    require(payload.length <= MAX_PAYLOAD_SIZE, "Payload size exceeds limit");
    
    // Rest of the function remains the same
    ...
}
```

## L-15: Unbounded Storage Growth in ChakraSettlement Contract

### Summary

The ChakraSettlement contract manages cross-chain transactions by storing data for both created and received transactions. This data is kept in two primary mapping structures: `create_cross_txs` and `receive_cross_txs`.

The contract stores data for every cross-chain transaction indefinitely. There is no mechanism implemented to clear old or processed transactions from these mappings. This leads to unbounded storage growth over time, which can have significant implications for contract performance and gas costs.

### Code Snippets

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/ChakraSettlement.sol#L11

```solidity
contract ChakraSettlement is BaseSettlement {
    mapping(uint256 => CreatedCrossChainTx) public create_cross_txs;
    mapping(uint256 => ReceivedCrossChainTx) public receive_cross_txs;

    // ... other contract code ...

    function send_cross_chain_msg(
        // ... parameters ...
    ) external {
        // ... other code ...

        create_cross_txs[txid] = CreatedCrossChainTx(
            txid,
            contract_chain_name,
            to_chain,
            from_address,
            from_handler,
            to_handler,
            payload,
            CrossChainMsgStatus.Pending
        );

        // ... emit event ...
    }

    function receive_cross_chain_msg(
        // ... parameters ...
    ) external {
        // ... other code ...

        receive_cross_txs[txid] = ReceivedCrossChainTx(
            txid,
            from_chain,
            contract_chain_name,
            from_address,
            from_handler,
            address(this),
            payload,
            CrossChainMsgStatus.Pending
        );

        // ... other code ...
    }

    // No functions to clear old data
}
```

### Impact
1. **Increasing Gas Costs**: As the storage size grows, operations that involve reading or writing to these mappings will become increasingly expensive in terms of gas.
2. **Contract Bloat**: The ever-increasing storage size will lead to blockchain bloat, increasing the resources required for nodes to maintain and sync the blockchain state.
3. **Potential DoS**: If the storage grows large enough, it could make certain operations prohibitively expensive or even impossible due to block gas limits.
4. **Reduced Performance**: Large storage can lead to slower contract execution times, affecting the overall performance of the cross-chain messaging system.
5. **Increased Operational Costs**: The growing state size increases the cost of running and maintaining nodes that need to store the full state.

### Scenario
1. The ChakraSettlement contract is deployed and begins processing cross-chain transactions.
2. Over time, thousands or millions of transactions are processed, each adding a new entry to either `create_cross_txs` or `receive_cross_txs`.
3. The contract's storage grows continuously, never removing old or completed transactions.
4. After a period of time (which could be months or years, depending on transaction volume), the storage size becomes so large that:
   - Gas costs for interacting with the contract become prohibitively expensive.
   - Some operations may fail due to exceeding block gas limits.
   - The blockchain nodes struggle to maintain the ever-growing state.

### Fix
To address this issue, consider implementing the following strategies:

1. **Implement a Clean-up Mechanism**:
   
```solidity
function cleanupOldTransactions(uint256[] calldata txids) external onlyOwner {
    for (uint256 i = 0; i < txids.length; i++) {
        uint256 txid = txids[i];
        if (create_cross_txs[txid].status != CrossChainMsgStatus.Pending) {
            delete create_cross_txs[txid];
        }
        if (receive_cross_txs[txid].status != CrossChainMsgStatus.Pending) {
            delete receive_cross_txs[txid];
        }
    }
}
```

2. **Implement Automatic Expiry**:
   Add a timestamp to each transaction and automatically remove transactions older than a certain age.

3. **Use a More Efficient Storage Pattern**:
   Consider using a circular buffer or other data structure that automatically overwrites old data.

4. **Separate Active and Archived Transactions**:
   Keep only active transactions in the main contract, and move completed transactions to a separate archival contract or off-chain storage.

5. **Implement Pagination**:
   If data needs to be kept for auditing purposes, implement pagination for data retrieval to manage gas costs.


## C-01: Malicious Whitelisted Handlers in ChakraSettlementHandler can Forge a Message to Mint an Arbitrary Amount of Tokens

## Summary
The ChakraSettlementHandler contract relies on a whitelist system to validate handlers for cross-chain transactions. While this provides a layer of security against unauthorized handlers, it doesn't protect against scenarios where a previously trusted, whitelisted handler becomes malicious.

Once a handler is whitelisted, the contract places implicit trust in all messages coming from that handler. This trust is not reevaluated on a per-transaction basis, leaving the contract vulnerable to exploitation if a whitelisted handler is compromised or turns malicious.

### Details
The vulnerability primarily lies in the `receive_cross_chain_msg` function:

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L300

```solidity
function receive_cross_chain_msg(
    uint256 txid,
    string memory from_chain,
    uint256 from_address,
    uint256 from_handler,
    PayloadType payload_type,
    bytes calldata payload,
    uint8 sign_type,
    bytes calldata signatures
) external onlySettlement returns (bool) {
    if (is_valid_handler(from_chain, from_handler) == false) {
        return false;
    }
    // ... rest of the function
}
```

Once the handler passes the `is_valid_handler` check, the contract processes the message without any additional validation of the payload's integrity or the legitimacy of the transaction.

### Impact
A malicious whitelisted handler could:
1. Forge cross-chain messages to mint or unlock tokens arbitrarily.
2. Manipulate token balances across chains.
3. Potentially drain funds from the contract or user accounts.
4. Disrupt the entire cross-chain ecosystem by sending invalid or malicious payloads.

### Scenario
1. A handler on Chain A is compromised by an attacker.
2. The attacker, now in control of a whitelisted handler, sends a cross-chain message to ChakraSettlementHandler on Chain B.
3. The message contains a forged ERC20 transfer payload, instructing the contract to mint a large amount of tokens to an address controlled by the attacker.
4. ChakraSettlementHandler on Chain B processes this message without additional checks, as it comes from a whitelisted handler.
5. Tokens are minted to the attacker's address, potentially depleting the token supply or causing economic damage.

### Fix
Implement additional security measures in the `receive_cross_chain_msg` function:

1. Add a multi-signature requirement for high-value transactions.
2. Implement rate limiting for transactions from each handler.
3. Add additional payload validation:

```solidity
function receive_cross_chain_msg(
    uint256 txid,
    string memory from_chain,
    uint256 from_address,
    uint256 from_handler,
    PayloadType payload_type,
    bytes calldata payload,
    uint8 sign_type,
    bytes calldata signatures
) external onlySettlement returns (bool) {
    if (is_valid_handler(from_chain, from_handler) == false) {
        return false;
    }
    
    // New checks
    require(validatePayloadIntegrity(payload), "Invalid payload");
    require(validateTransactionLimit(from_handler), "Transaction limit exceeded");
    require(validateMultiSigIfRequired(payload, signatures), "Multi-sig check failed");
    
    // ... rest of the function
}

function validatePayloadIntegrity(bytes calldata payload) internal pure returns (bool) {
    // Implement payload validation logic
}

function validateTransactionLimit(uint256 handler) internal view returns (bool) {
    // Implement rate limiting logic
}

function validateMultiSigIfRequired(bytes calldata payload, bytes calldata signatures) internal view returns (bool) {
    // Implement multi-signature validation for high-value transactions
}
```

## C-02: Lack of Time-Delayed Execution for Critical Parameter Changes

### Summary
The `SettlementSignatureVerifier` contract allows immediate changes to critical parameters, such as the required number of validators, without any time delay or additional security measures.

### Details
The `set_required_validators_num` function can be called by any address with the `MANAGER_ROLE`, and the changes take effect immediately. This immediate execution of critical parameter changes could be risky, especially if a manager's account is compromised or if there's a need for additional oversight on such changes.

### Code Snippet

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/SettlementSignatureVerifier.sol#L92

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/SettlementSignatureVerifier.sol#L139

```solidity
function set_required_validators_num(uint256 _required_validators) external virtual onlyRole(MANAGER_ROLE) {
    uint256 old = required_validators;
    required_validators = _required_validators;
    emit RequiredValidatorsChanged(msg.sender, old, required_validators);
}
```

### Impact
1. A compromised manager account could immediately change the required number of validators, potentially to a very low number, making it easier to push through malicious transactions.
2. There's no window for other stakeholders to review and potentially contest significant changes to the contract's operation.
3. Accidental misconfigurations could immediately affect the contract's behavior without any safeguard.

### Scenario
A manager's private key is compromised. The attacker immediately reduces the required number of validators to 1 and adds themselves as a validator. They can now single-handedly approve any transaction, bypassing the intended security of the multi-signature setup.

### Fix
Implement a time-delay mechanism for critical parameter changes using OpenZeppelin's `TimelockControllerUpgradeable`.

1. Import the `TimelockControllerUpgradeable` contract:
```solidity
import {TimelockControllerUpgradeable} from "@openzeppelin/contracts-upgradeable/governance/TimelockControllerUpgradeable.sol";
```

2. Add a `TimelockControllerUpgradeable` instance to the contract:
```solidity
TimelockControllerUpgradeable public timelock;
```

3. Initialize the `TimelockControllerUpgradeable` in the `initialize` function:
```solidity
function initialize(address _owner, uint256 _required_validators) public initializer {
    // ... existing initializations

    address[] memory proposers = new address[](1);
    proposers[0] = _owner;
    address[] memory executors = new address[](1);
    executors[0] = address(0); // Allow any address to execute
    timelock = new TimelockControllerUpgradeable(1 days, proposers, executors, _owner);
}
```

4. Modify the `set_required_validators_num` function to create a timelocked proposal:
```solidity
function set_required_validators_num(uint256 _required_validators) external onlyRole(MANAGER_ROLE) {
    bytes memory data = abi.encodeWithSelector(this.executeRequiredValidatorsChange.selector, _required_validators);
    timelock.schedule(address(this), 0, data, bytes32(0), bytes32(0), 1 days);
}

function executeRequiredValidatorsChange(uint256 _new_required_validators) external {
    require(msg.sender == address(timelock), "Only timelock can execute");
    uint256 old = required_validators;
    required_validators = _new_required_validators;
    emit RequiredValidatorsChanged(msg.sender, old, required_validators);
}
```

These changes introduce a 1-day delay before critical parameter changes take effect. This delay provides a window for stakeholders to review proposed changes and potentially take action if the changes are deemed problematic. It significantly enhances the security of the contract by preventing immediate, potentially malicious changes to critical parameters.

The timelock also adds an additional layer of governance, as it allows for a more controlled and transparent process for making important changes to the contract's configuration.
