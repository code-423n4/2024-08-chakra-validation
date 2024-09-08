
## [L-01] Missing Chain ID in txid Calculation

https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L122

Without a unique Chain ID, there is a risk that identical transactions across different chains could produce the same txid, leading to potential conflicts, replay attacks, or unintended behavior.

```javascript
/**
     * @dev Function to send cross-chain message
     * @param to_chain The chain to send the message to
     * @param from_address The address sending the message
     * @param to_handler The handler to handle the message
     * @param payload_type The type of the payload
     * @param payload The payload of the message
     */
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
                    contract_chain_name, // from chain // @ audit what about the chain id
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

# Proof of Concept (PoC):

An attacker might exploit the missing Chain ID by executing the following steps:

- Suppose a valid transaction A is initiated on Chain 1 with a specific set of parameters and a generated txid.
  The same transaction parameters (excluding the chain identifier) are then used to create a similar transaction B on Chain 2.
  Identical txid Generation:

- Since the Chain ID is not included in the txid calculation, both transactions A and B would generate the same txid.
  Replay Attack:

- The attacker could capture the message from Chain 1 and replay it on Chain 2, causing the system to believe the same transaction is being processed, potentially leading to the execution of unintended actions or double processing.
  Cross-Chain Confusion:

- If the receiving contract is not designed to differentiate between chains, it may incorrectly process the replayed transaction, leading to incorrect outcomes or financial losses.

# Recommendation:

include the Chain ID as part of the txid calculation.

```javascript
abi.encodePacked(
                    contract_chain_name, // from chain // @ audit what about the chain id
                    chain_id // add this line
                    to_chain,
                    from_address, // msg.sender address
                    from_handler, // settlement handler address
                    to_handler,
                    nonce_manager[from_address]
                )
```

## [L-02] Inconsistent Type of to_handler (uint256 vs. address)

https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L114

The inconsistent treatment of `to_handler` as uint256 in `send_cross_chain_msg` and as `address` in `receive_cross_chain_msg`

```javascript
function receive_cross_chain_msg(
        uint256 txid,
        string memory from_chain,
        uint256 from_address,
        uint256 from_handler,
        address to_handler, // @audit this is address
        PayloadType payload_type,
        bytes calldata payload,
        uint8 sign_type, // validators signature type /  multisig or bls sr25519
        bytes calldata signatures // signature array
    ) external {}
```

```javascript
function send_cross_chain_msg(
        string memory to_chain,
        address from_address,
        uint256 to_handler, //@audit this is uint256
        PayloadType payload_type,
        bytes calldata payload
    ) external {}
```


```javascript
function processCrossChainCallback(
        uint256 txid,
        string memory from_chain,
        uint256 from_handler,
        address to_handler, //@audit this is address
        CrossChainMsgStatus status,
        uint8 sign_type,
        bytes calldata signatures
    ) internal {}
```
Note that from_handler is also included as a type uint256 and also as address in some places ie it is set to msg.sender when send_cross_chain_msg is called according to docs

```
@param from_handler Handler address on the origin chain
```

this inconsistency can lead to serious issues in message integrity, signature verification, and overall logic execution. at the moment `from_handler` is the `msg.sender` which means the vice versa will be the `to_handler`

```javascript
 address from_handler = msg.sender;
```
to_handler is part of the txid which at the moment is of type uint256

```javascript
function send_cross_chain_msg(
        string memory to_chain,
        address from_address,
        uint256 to_handler,
        PayloadType payload_type,
        bytes calldata payload
    ) external {
        ...
        uint256 txid = uint256(
            keccak256(
                abi.encodePacked(
                    contract_chain_name, // from chain // @ audit what about the chain id
                    to_chain,
                    from_address, // msg.sender address
                    from_handler, // settlement handler address
                    to_handler, //@audit this is uint256?
                    nonce_manager[from_address]
                )
    }
```

When the `to_handler` is handled as a `uint256` in one function and `address` in another, it could lead to an incorrect interpretation of the handler address. This might result in the system sending messages to the wrong handler or failing to process legitimate messages.

Hash Mismatch: The generation of txid in send_cross_chain_msg includes the to_handler variable as uint256. When the message is processed in receive_cross_chain_msg, to_handler is treated as address. The different interpretations of this variable may cause a mismatch in the keccak256 hash, which can lead to failed signature verifications, allowing attackers to either bypass checks or cause valid transactions to fail.

Cross-Chain Interoperability Issues: Systems expecting consistent address types may experience errors when interacting with the handler because of the type mismatch, causing failures in processing cross-chain messages.

Proof of Concept (PoC): Consider the following scenario:

In the send_cross_chain_msg function:

```javascript
function send_cross_chain_msg(
    string memory to_chain,
    address from_address,
    uint256 to_handler,  // Declared as uint256
    PayloadType payload_type,
    bytes calldata payload
) external {
    address from_handler = msg.sender;

    uint256 txid = uint256(
        keccak256(
            abi.encodePacked(
                contract_chain_name, 
                to_chain,
                from_address, 
                from_handler, 
                to_handler,  // Treated as uint256
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
In the receive_cross_chain_msg function:

```javascript
function receive_cross_chain_msg(
    uint256 txid,
    string memory from_chain,
    uint256 from_address,
    uint256 from_handler,
    address to_handler,  // Declared as address
    PayloadType payload_type,
    bytes calldata payload,
    uint8 sign_type, 
    bytes calldata signatures
) external {
    // Signature verification
    bytes32 message_hash = keccak256(
        abi.encodePacked(
            txid,
            from_chain,
            from_address,
            from_handler,
            to_handler,  // Treated as address here
            keccak256(payload)
        )
    );

    require(
        signature_verifier.verify(message_hash, signatures, sign_type),
        "Invalid signature"
    );

    // Further logic omitted for brevity...
}
```
`to_handler` is declared as `uint256` in `send_cross_chain_msg` but as `address` in `receive_cross_chain_msg` and `verifySignature`. This will break some functionality

# Recommendation:

Ensure that to_handler is consistently treated as either an address throughout the entire contract. Based on its role as a handler, it should logically be treated as an address.

## [L-03] receive_cross_chain_msg Lacks Explicit Nonce, Potentially Allowing Replay Attacks

https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L170

The absence of an explicit nonce in the receive_cross_chain_msg function introduces the potential for replay attacks. Since the function relies solely on the txid for uniqueness, an attacker could exploit this by resending a previously valid message, potentially causing it to be processed multiple times. This could lead to unauthorized actions being performed, compromising the integrity of the cross-chain messaging system.

# Proof of Concept (PoC):

An attacker captures a valid cross-chain message and its associated signature.
The attacker resends the exact same message to the receive_cross_chain_msg function.
Since the function only checks the txid and does not include an explicit nonce in its verification, there is a risk that the message could be processed again, especially if the transaction status has not been properly updated.

# Recommendation:
Introduce a dedicated nonce parameter within the receive_cross_chain_msg function. This nonce should increment with each new message and be included in the signature verification process. By doing so, the function can ensure that each message is unique and cannot be replayed, thus preventing potential replay attacks and enhancing the overall security of the cross-chain messaging system.

## [L-04] add_manager Function Lacks a Check for Existing Manager Role
Impact:

https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/SettlementSignatureVerifier.sol#L83

The add_manager function currently grants the MANAGER_ROLE to the specified _manager address without verifying whether the address already possesses this role. This oversight can lead to potential inefficiencies and unintended consequences, such as:

Redundant Role Assignments: Without a check, the function could grant the MANAGER_ROLE multiple times to the same address, leading to unnecessary role assignments. While this may not directly impact functionality, it can clutter the contract’s role management system and make auditing and managing roles more difficult.

## Proof of Concept (PoC):

Consider the following scenario where the add_manager function is called:

```javascript
function add_manager(address _manager) external onlyOwner {
    grantRole(MANAGER_ROLE, _manager);
    emit ManagerAdded(msg.sender, _manager);
}
```
If _manager already has the MANAGER_ROLE, calling add_manager again for the same _manager address would result in the role being granted again, which is redundant.

# Recommendation

Include a check that ensures the _manager address does not already have the MANAGER_ROLE

```javascript
function add_manager(address _manager) external onlyOwner {
    require(!hasRole(MANAGER_ROLE, _manager), "Address is a manager already");
    grantRole(MANAGER_ROLE, _manager);
    emit ManagerAdded(msg.sender, _manager);
}

```

## [L-05] Lack of Nonce in verifySignature Function May Lead to Replay Attacks

https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L285

The verifySignature function currently lacks a nonce parameter, which could make it vulnerable to replay attacks. Replay attacks occur when a valid data transmission is maliciously or fraudulently repeated or delayed. Without a nonce, an attacker could reuse the same transaction ID (txid) and signatures to replay the message, potentially leading to unauthorized actions being taken on the blockchain, such as double-executions or fraudulent state changes.

# Proof of Concept (PoC):
The current implementation of the verifySignature function is as follows:

```javascript
function verifySignature(
    uint256 txid,
    uint256 from_handler,
    address to_handler,
    CrossChainMsgStatus status,
    uint8 sign_type,
    bytes calldata signatures
) internal view {
    bytes32 message_hash = keccak256(
        abi.encodePacked(txid, from_handler, to_handler, status)
    );

    require(
        signature_verifier.verify(message_hash, signatures, sign_type),
        "Invalid signature"
    );
}
```
In this implementation, there is no nonce or other mechanism to ensure that the message is unique for each transaction. As a result, an attacker could capture a valid transaction and replay it to perform the same action multiple times, as the message_hash would be identical.

Adding a nonce to the verifySignature function can mitigate this risk. This ensures that each transaction has a unique message_hash, even if all other parameters remain the same, effectively preventing replay attacks.

The function is also missing a deadline which is also very important 

# Recommendation:
Include a nonce parameter in the verifySignature function to ensure that each transaction is unique and to prevent replay attacks. The nonce should be incremented or otherwise guaranteed to be unique for each transaction. The updated function should look like this:

```javascript
function verifySignature(
    uint256 txid,
    uint256 from_handler,
    address to_handler,
    CrossChainMsgStatus status,
    uint8 sign_type,
    bytes calldata signatures,
    uint256 nonce
) internal view {
    bytes32 message_hash = keccak256(
        abi.encodePacked(txid, from_handler, to_handler, status, nonce)
    );

    require(
        signature_verifier.verify(message_hash, signatures, sign_type),
        "Invalid signature"
    );
}
```

## [L-06] Incorrect ERC20 Function Calls in Settlement Modes

https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/ChakraSettlementHandler.sol#L125

The current implementation of the `cross_chain_erc20_settlement` function inaccurately calls the _erc20_lock function for most settlement modes, regardless of the required behavior. This mismatch can lead to incorrect token operations, such as locking tokens when they should be unlocked or burned, and failing to mint tokens when required. The primary impact is that cross-chain settlements may not function as intended, potentially leading to incorrect token balances or frozen assets, affecting the integrity of the cross-chain transfer process.

# Proof of Concept (PoC):
The relevant part of the function logic is as follows:

```javascript
if (mode == SettlementMode.MintBurn) {
    _erc20_lock(msg.sender, address(this), amount);
} else if (mode == SettlementMode.LockUnlock) {
    _erc20_lock(msg.sender, address(this), amount);
} else if (mode == SettlementMode.LockMint) {
    _erc20_lock(msg.sender, address(this), amount);
} else if (mode == SettlementMode.BurnUnlock) {
    _erc20_burn(msg.sender, amount);
}
```

Based on the functions below each mode should be handled accoridngly to avoid any issues

```javascript

    function _erc20_mint(address account, uint256 amount) internal {
        IERC20Mint(token).mint_to(account, amount);
    }

    function _erc20_burn(address account, uint256 amount) internal {
        require(
            IERC20(token).balanceOf(account) >= amount,
            "Insufficient balance"
        );

        IERC20Burn(token).burn_from(account, amount);
    }

    /**
     * @dev Lock erc20 token
     * @param from The lock token from account
     * @param to The locked token to account
     * @param amount The amount to unlock
     */
    function _erc20_lock(address from, address to, uint256 amount) internal {
        _safe_transfer_from(from, to, amount);
    }

    /**
     * @dev Unlock erc20 token
     * @param to The token unlocked to account
     * @param amount The amount to unlock
     */
    function _erc20_unlock(address to, uint256 amount) internal {
        _safe_transfer(to, amount);
    }
```
By calling `_erc20_lock` in most of the modes there is a missmatch.

At the moment, for the MintBurn, LockUnlock, and LockMint modes, the function only calls _erc20_lock, regardless of the specific mode’s requirements. However, each mode has a distinct flow for handling token operations during cross-chain transfers:

MintBurn should burn tokens on the source chain and mint tokens on the destination chain.
LockUnlock should lock tokens on the source chain and unlock them on the destination chain.
LockMint should lock tokens on the source chain and mint new tokens on the destination chain.
BurnUnlock should burn tokens on the source chain and unlock tokens on the destination chain.
Currently, the logic does not reflect these flows properly, which could lead to errors in cross-chain settlements.

# Recommendetion:
Each settlement mode should have its own specific function calls to handle the token transfers correctly. for example

```javascript
 else if (mode == SettlementMode.LockUnlock) {
            _erc20_unlock( address(this), amount);
 }
```
## [L-07] Upgradable Contracts Lack Initializer Protection

The contracts are upgradable but lack protection to prevent multiple initializations. In the context of upgradable smart contracts, constructors are not used; instead, an initializer function is used to set up the initial state. Without proper protection, such as a constructor that disables the initializer after the first call, anyone could potentially reinitialize the contract, allowing them to overwrite the state, which can lead to severe consequences like loss of control over critical contract variables or even full compromise of contract logic.

A malicious actor could call the initializer function again and reset key variables such as ownership or token balances, essentially gaining control of the contract and performing unauthorized actions, including draining funds or modifying business-critical configurations.

# Recommendation
To prevent reinitialization vulnerabilities in upgradable contracts, a constructor that disables the initializer function should be added:

```javascript
constructor() {
        _disableInitializers();  // Prevents further calls to initializer functions
    }
```