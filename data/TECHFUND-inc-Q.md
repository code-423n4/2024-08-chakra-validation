### ERC20Method enum has typos

```solidity
   enum ERC20Method {
==>    Unkown, // 0: Unknown method (also serves as default)
    Transfer, // 1: Transfer tokens from one address to another
==>    Arppvoe, // 2: Approve spending of tokens (Note: there's a typo, should be "Approve")
    TransferFrom, // 3: Transfer tokens on behalf of another address
    Mint, // 4: Create new tokens
    Burn // 5: Destroy existing tokens
}
```

### ChakraSettlementHandler::cross_chain_erc20_settlement()
the `cross_chain_erc20_settlement()` function should check that the `to_chain` and `chain` are of different values.  This ensure that message is always cross chain and does not allow the caller to send message to the same chain. 

### ChakraSettlementHandler::_safe_transfer_from() & _safe_transfer()
The implementation of safe transfer functions are not from openzeppelin. They are implemented locally. Post transfer, the balance can be checked to verify if the funds moved from one account to another like how it is implemented in openzeppelin library