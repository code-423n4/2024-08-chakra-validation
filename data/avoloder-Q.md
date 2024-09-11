# [L-01] ReceivedCrossChainTx struct is wrongly populated in ChakraSettlement.sol in the function `receive_cross_chain_msg()`
The struct has following definition: 
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
However in the function `receive_cross_chain_msg()` it is populated as follows: 
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

We can see that `address(this)` is used for the `to_handler` address which is incorrect, since `address(this)` represents the address of the Settlement contract and not the Handler. 

# Proof of Concept 
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/ChakraSettlement.sol#L17-L26

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/ChakraSettlement.sol#L205-L214

# Recommended Mitigation Steps
Pass the `to_handler` address from the signature to the struct and not `address(this)`
