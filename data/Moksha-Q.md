### [L-01] Missing validation in the source chain if the destination chain handler is in the source chain whitelist. 

### Impact
The validation of the destination chain/target chain handler is needed in the source chain from where the message needs to be originated as mentioned in the main invariant point 
> • The handler receiving a cross-chain message must be on the whitelist for the source chain

But neither Starknet nor the EVM side of the code has this. Users can just specify any nonzero handler as both sides of the code just validate null inputs. Though the impact is low it breaks the invariant mentioned above.

### Code Snippet
EVM `cross_chain_settelmenet.sol` function
Paste Perma Link
```
```
Starknet Cairo `crossc_chain_settlement.cairo` function
Paste Perma Link
```
```
### Recommendation
As the invariant documentation mentioned add the validation for the receiving end `handler` address as contract already maintains the whitelist of valid handler in the form of `from_chain` and `from_handler`

### [L-02] Use the latest version of OpenZeppelin contracts in Cairo

### Impact
The contract or project uses the old `oz` version of the contract which happened to have a medium severity issue that got fixed and upgraded to the latest version `v16.0` recently, since the project has Starknet contracts using the oz `Ownable mixin component` where the issue was identified. It would be wise to use the latest.

Full version release notes of `oz` https://github.com/OpenZeppelin/cairo-contracts/releases/tag/v0.16.0

The issue described at https://github.com/OpenZeppelin/cairo-contracts/pull/1122

### Recommendation
Use upgraded and fixed version of `oz` cairo contracts `v16.0`

### [L-03] The required validator number variable and remove validator function could be not in sync

### Impact
