# [L-0] Function does not follow the CEI and can cause burning extra tokens

### Found in: 
`https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/ChakraSettlementHandler.sol#L383-#L389`

### Mitigations: 
First set the status and then burn tokens

```diff
if (status == CrossChainMsgStatus.Success) {
+   create_cross_txs[txid].status = CrossChainTxStatus.Settled;

    if (mode == SettlementMode.MintBurn) {
        _erc20_burn(address(this), create_cross_txs[txid].amount);
    }

-    create_cross_txs[txid].status = CrossChainTxStatus.Settled;
}
```
