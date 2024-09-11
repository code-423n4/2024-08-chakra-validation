## Finding Summary 

| ID | Description | Severity |
| - | - | :-: |
| [L-01](#l-01-avoid-directly-minting-follow-nfts-to-the-profile-owner-in-processblock) | `toChain` address is not verified in `receive_cross_chain_msg()` on Ethereum | Low |
| [L-02](#l-01-avoid-directly-minting-follow-nfts-to-the-profile-owner-in-processblock) | Message hash is generated differently on Ethereum and Starknet | Low |
| [L-03](#l-01-avoid-directly-minting-follow-nfts-to-the-profile-owner-in-processblock) | Deviations between chains when creating `received_tx` | Low |
| [L-04](#l-01-avoid-directly-minting-follow-nfts-to-the-profile-owner-in-processblock) | `CrossChainHandleResult` event has different params between chains | Low |
| [L-05](#l-01-avoid-directly-minting-follow-nfts-to-the-profile-owner-in-processblock) | Insufficient validation of callback parameters on Ethereum | Low |
| [L-06](#l-01-avoid-directly-minting-follow-nfts-to-the-profile-owner-in-processblock) | `created_tx` is incorrectly created again after calling the handler contract on Starknet | Low |
| [L-07](#l-01-avoid-directly-minting-follow-nfts-to-the-profile-owner-in-processblock) | `receive_cross_chain_msg()` and `receive_cross_chain_callback()` miss access control on Ethereum | Low |
| [L-08](#l-01-avoid-directly-minting-follow-nfts-to-the-profile-owner-in-processblock) | `receive_cross_chain_msg()` and `receive_cross_chain_callback()` miss access control on Starknet| Low |
| [L-09](#l-01-avoid-directly-minting-follow-nfts-to-the-profile-owner-in-processblock) | enum `TxStatus` from `ChakraSettlementHandler` is unused | Low |



## [L-01] `toChain` address is not verified in `receive_cross_chain_msg()` on Ethereum

`receive_cross_chain_msg()` has not any `toChain` verification the same way it's done on Starknet:

https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L170-180
```
function receive_cross_chain_msg(
        uint256 txid,
        string memory from_chain,
        uint256 from_address,
        uint256 from_handler,
        address to_handler,
        PayloadType payload_type,
        bytes calldata payload,
        uint8 sign_type, // validators signature type /  multisig or bls sr25519
        bytes calldata signatures // signature array
    ) 
```

https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L337
```
  assert(to_chain == self.chain_name.read(), 'error to_chain');
```

`to_chain` should correspond to the chain of the settlement contract. Otherwise, some unexpected scenarios can occur when the settlement of the incorrect chain is called.

### Recommendation

Include `to_chain` check in the parameters of the `receive_cross_chain_msg()`.




## [L-02] Message hash is generated differently on Ethereum and Starknet

On both Ethereum and Starknet, message hash is generated differently when verifying signatures:


https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L340
```
 let mut message_hash: felt252 = LegacyHash::hash(from_chain, (cross_chain_msg_id, to_chain, from_handler, to_handler));
```

https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L293-295
```
 bytes32 message_hash = keccak256(
            abi.encodePacked(txid, from_handler, to_handler, status)
        );
```

As the contract should be compatible (Ethereum -> Starknet messaging is supported as well), such deviations can lead to incorrect behavior in the future as there can be different parameters loaded to the Chakra network from the source chain.

### Recommendation

Generate message hash similarly on Ethereum and Cairo to avoid incompatibility errors.



## [L-03] Deviations between chains when creating `received_tx`

On Ethereum and Starknet, there are differences when creating a new entry point for `received_tx` mapping:


https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L205-214
```
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


```

https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L363-370
```
 self.received_tx.write(cross_chain_msg_id, ReceivedTx{
                tx_id:cross_chain_msg_id,
                from_chain: from_chain,
                from_handler: from_handler,
                to_chain: to_chain,
                to_handler: to_handler,
                tx_status: status
            });
```

As you can see, on Cairo, there are no `payload`, `contract_chain_name`, `from_address` fields being used. As the contract should be compatible (Ethereum -> Starknet messaging is supported as well), such deviations can lead to incorrect behavior in the future as there can be different parameters loaded to the Chakra network from the source chain.
 
### Recommendation

Ensure that the implementation of the `receive_cross_msg()` is identical on both chains to ensure compatibility.


## [L-04] `CrossChainHandleResult` event has different params between chains

Take a look at what params `CrossChainHandleResult` has on Ethereum and Starknet:

https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L373-381
```
self.emit(CrossChainHandleResult{
                cross_chain_settlement_id: cross_chain_msg_id,
                from_chain: to_chain,
                from_handler: to_handler,
                to_chain: from_chain,
                to_handler: from_handler,
                cross_chain_msg_status: status,
                payload_type: payload_type
            });
```

https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L235-243
```
    emit CrossChainHandleResult(
            txid,
            status,
            contract_chain_name,
            from_chain,
            address(to_handler),
            from_handler,
            payload_type
        );
```

Such deviations may lead to the confusion and mistakes as the information that's contained in the events is monitored by off-chain services (Chakra network).
 
### Recommendation

Implement both events identically to avoid unexpected behavior in the future.


## [L-05] Insufficient validation of callback parameters on Ethereum

On Starknet, when receiving callback from the destination chain, all the params are validated against the `created_tx`:

https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L404-409
```
  assert(self.created_tx.read(cross_chain_msg_id).tx_id == cross_chain_msg_id, 'message id error');
            assert(self.created_tx.read(cross_chain_msg_id).from_chain == to_chain, 'from_chain error');
            assert(self.created_tx.read(cross_chain_msg_id).to_chain == from_chain, 'to_chain error');
            assert(self.created_tx.read(cross_chain_msg_id).from_handler == to_handler, 'from_handler error');
            assert(self.created_tx.read(cross_chain_msg_id).to_handler == from_handler, 'to_handler error');
            assert(self.created_tx.read(cross_chain_msg_id).tx_status == CrossChainMsgStatus::PENDING, 'tx status error');

```

However, on Ethereum, only status is verified in `processCrossChainCallback()`:

https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L312-315
```
   require(
            create_cross_txs[txid].status == CrossChainMsgStatus.Pending,
            "Invalid transaction status"
        );
```

This can lead to the callback being incompatible with the initial params of the created cross chain tx on the source chain.

 
### Recommendation

Ensure every parameter in the callback corresponds properly to the params from the `create_cross_txs[txid]`.


## [L-06] `created_tx` is incorrectly created again after calling the handler contract on Starknet

After receiving the callback from the destination chain and calling the `receive_cross_chain_callback()`, the function in the settlement updates the message that corresponds to the `cross_chain_msg_id`. The problem is that it misses the status parameter at the end making it the default value instead of `SETTLED`.

### Recommendation

Change these lines

https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L423-430
```
  self.created_tx.write(cross_chain_msg_id, CreatedTx{
                tx_id:cross_chain_msg_id,
                tx_status:state,
                from_chain: to_chain,
                to_chain: from_chain,
                from_handler: to_handler,
                to_handler: from_handler
            });

```

And add the correct status parameter.




## [L-07] `receive_cross_chain_msg()` and `receive_cross_chain_callback()` miss access control on Ethereum

In the current implementation of `ChakraSettlement` smart contract, `receive_cross_chain_msg()` and `receive_cross_chain_callback()` miss access control meaning anybody can call the functions. This can lead to some unexpected scenarios where users can manipulate the values that are sent by the Chakra Network:

https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L256-264
```
function receive_cross_chain_callback(
        uint256 txid,
        string memory from_chain,
        uint256 from_handler,
        address to_handler,
        CrossChainMsgStatus status,
        uint8 sign_type,
        bytes calldata signatures
    ) external {

```

https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L170-180
```
 function receive_cross_chain_msg(
        uint256 txid,
        string memory from_chain,
        uint256 from_address,
        uint256 from_handler,
        address to_handler,
        PayloadType payload_type,
        bytes calldata payload,
        uint8 sign_type, // validators signature type /  multisig or bls sr25519
        bytes calldata signatures // signature array
    ) external 


```

### Recommendation

Implement `onlyNetwork` modifier or create some other functionality to prevent users from calling the sensitive functions.


## [L-08] `receive_cross_chain_msg()` and `receive_cross_chain_callback()` miss access control on Starknet


In the current implementation of `settlement` smart contract, `receive_cross_chain_msg()` and `receive_cross_chain_callback()` miss access control meaning anybody can call the functions. This can lead to some unexpected scenarios where users can manipulate the values that are sent by the Chakra Network:

https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L393-403
```
  fn receive_cross_chain_callback(
            ref self: ContractState,
            cross_chain_msg_id: felt252,
            from_chain: felt252,
            to_chain: felt252,
            from_handler: u256,
            to_handler: ContractAddress,
            cross_chain_msg_status: u8,
            sign_type: u8,
            signatures: Array<(felt252, felt252, bool)>,
        ) -> bool 

```

https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L325-336
```
   fn receive_cross_chain_msg(
            ref self: ContractState,
            cross_chain_msg_id: u256,
            from_chain: felt252,
            to_chain: felt252,
            from_handler: u256,
            to_handler: ContractAddress,
            sign_type: u8,
            signatures: Array<(felt252, felt252, bool)>,
            payload: Array<u8>,
            payload_type: u8,
        ) -> bool

```

### Recommendation

Implement proper access control to prevent users from calling the sensitive functions.



## [L-09] Enum `TxStatus` is from `ChakraSettlementHandler` is unsused

In the current version of `ChakraSettlementHandler`, `TxStatus` is not used somehow. Instead, `CrossChainTxStatus` is actively used:

https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/ChakraSettlementHandler.sol#L27-33
```
 enum TxStatus {
        Unknow,
        Pending,
        Minted,
        Burned,
        Failed
    }

```

### Recommendation

Use `TxStatus` enum or delete it.
