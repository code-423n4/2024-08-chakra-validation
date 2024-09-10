## [L-01] wrong address stored in created_tx mapping
### Proof of Concept
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/handler_erc20.cairo#L184-L194
`from` should be caller of `cross_chain_erc20_settlement` function. `get_contract_address()` is equal to `address(this)` in solidity. `get_caller_address()` is equal to `msg.sender` in solidity.
### Recommended Mitigation Steps
```diff
            let tx: CreatedCrossChainTx = CreatedCrossChainTx{
                    tx_id: tx_id,
                    from_chain: from_chain,
                    to_chain: to_chain,
-                   from: get_contract_address(),
+                   from: get_caller_address(),                    
                    to: to,
                    from_token: self.token_address.read(),
                    to_token: to_token,
                    amount: amount,
                    tx_status: CrossChainTxStatus::PENDING
                };
```
## [L-02] wrong address stored in create_cross_txs mapping
### Proof of Concept
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L154-L164
```
    struct CreatedCrossChainTx {
       uint256 txid;
        string from_chain;
        string to_chain;
        address from;
        uint256 to;
        address from_token;
        uint256 to_token;
        uint256 amount;
        CrossChainTxStatus status;
    }
```
According to the definition of struct CreatedCrossChainTx, `address(this)` should be changed to `token`.
### Recommended Mitigation Steps
```diff
            create_cross_txs[txid] = CreatedCrossChainTx(
-               txid, chain, to_chain, msg.sender, to, address(this), to_token, amount, CrossChainTxStatus.Pending
+               txid, chain, to_chain, msg.sender, to, token, to_token, amount, CrossChainTxStatus.Pending
            );
```
## [L-03] wrong address stored in receive_cross_txs mapping
### Proof of Concept
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/ChakraSettlement.sol#L205-L214
```
    struct ReceivedCrossChainTx {
        uint256 txid;
        string from_chain;
        string to_chain;
        uint256 from_address;
        uint256 from_handler;
        address to_handler;
        bytes payload;
        CrossChainMsgStatus status;
    }
```
According to the definition of struct ReceivedCrossChainTx, `address(this)` should be changed to `to_handler`.
### Recommended Mitigation Steps
```diff
        receive_cross_txs[txid] = ReceivedCrossChainTx(
            txid,
            from_chain,
            contract_chain_name,
            from_address,
            from_handler,
-           address(this),
+           to_handler,
            payload,
            CrossChainMsgStatus.Pending
        );
```
## [L-04] wrong emit parameter about CrossChainLocked event
### Proof of Concept
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L212-L222
```
    event CrossChainLocked(
        uint256 indexed txid,
        address indexed from,
        uint256 indexed to,
        string from_chain,
        string to_chain,
        address from_token,
        uint256 to_token,
        uint256 amount,
        SettlementMode mode
    );
```
According to the definition of event CrossChainLocked, `address(this)` should be changed to `token`.
### Recommended Mitigation Steps
```diff
-       emit CrossChainLocked(txid, msg.sender, to, chain, to_chain, address(this), to_token, amount, mode);
+       emit CrossChainLocked(txid, msg.sender, to, chain, to_chain, token, to_token, amount, mode);
```
## [L-05] wrong emit parameter about CrossChainResult event
### Proof of Concept
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/settlement.cairo#L432-L440
`get_tx_info().unbox().account_contract_address` is the account contract from which this transaction originates. It's inconsistent with CrossChainResult in solidity code. In solidity code:
```
        emit CrossChainResult(
            txid,
            create_cross_txs[txid].from_chain,
            create_cross_txs[txid].to_chain,
            create_cross_txs[txid].from_address,
            create_cross_txs[txid].from_handler,
            create_cross_txs[txid].to_handler,
            create_cross_txs[txid].status
        );
    }
```
It includes initiator of cross chain message rather than caller of `receive_cross_chain_callback`. 
### Recommended Mitigation Steps
Recommend to add `from_address` as input of `send_cross_chain_msg` function and store it to `created_tx` mapping. And retrieve it to event CrossChainResult.

## [L-06] If to_handler's address is the same across different chains, signature could be replayed
### Proof of Concept
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/ChakraSettlement.sol#L183-L197
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/ChakraSettlement.sol#L285-L301
The `to_chain` is not included in the signature hash. So if to_handler's address is the same across different chains (not very likely), the signature which is valid on one chain can be replayed in another chain.
### Recommended Mitigation Steps
Add `to_chain` field to compute signature hash.