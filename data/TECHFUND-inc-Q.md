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