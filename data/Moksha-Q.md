### [L-01] Missing validation in the source chain if the destination chain handler is in the source chain whitelist. 

### Impact
The validation of the destination chain/target chain handler is needed in the source chain from where the message needs to be originated as mentioned in the main invariant point 
> • The handler receiving a cross-chain message must be on the whitelist for the source chain

But the EVM side of the code has this. Users can just specify any nonzero handler as both the code just validate null inputs. Though the impact is low it breaks the invariant mentioned above.

### Code Snippet
EVM `cross_chain_settelmenet.sol` function in `ChakraSettlementHandler.sol` contract
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L111-L223
```
 require(amount > 0, "Amount must be greater than 0");
        require(to != 0, "Invalid to address");
        require(to_handler != 0, "Invalid to handler address");
        require(to_token != 0, "Invalid to token address");

        if (mode == SettlementMode.MintBurn) {
            _erc20_lock(msg.sender, address(this), amount);
        } else if (mode == SettlementMode.LockUnlock) {
            _erc20_lock(msg.sender, address(this), amount);
        } else if (mode == SettlementMode.LockMint) {
            _erc20_lock(msg.sender, address(this), amount);
        } else if (mode == SettlementMode.BurnUnlock) {
            _erc20_burn(msg.sender, amount);
        }
// snip
```

### Recommendation
As the invariant documentation mentioned add the validation for the receiving end `handler` address as contract already maintains the whitelist of valid handler in the form of `from_chain` and `from_handler`
```
function cross_chain_erc20_settlement(
        string memory to_chain,
        uint256 to_handler,
        uint256 to_token,
        uint256 to,
        uint256 amount
    ) external {
// null validation snip
 require(is_valid_handler(to_chain, to_handler) == false),'not support handler')
// snip
}
```

### [L-02] Use the latest version of OpenZeppelin contracts in Cairo

### Impact
The contract or project uses the old `oz` version `v0.14.0` of the contract which happened to have a medium severity issue that got fixed and upgraded to the latest version `v0.16.0` recently, since the project has Starknet contracts using the oz `Ownable mixin component` where the issue was identified. It would be wise to use the latest.

Full version release notes of `oz` https://github.com/OpenZeppelin/cairo-contracts/releases/tag/v0.16.0

The issue described at https://github.com/OpenZeppelin/cairo-contracts/pull/1122

### Recommendation
Use upgraded and fixed version of `oz` cairo contracts `v16.0`

### [L-03] The required validator number variable and remove validator function could be not in sync

### Impact
Generally, the admin calls are assumed to be safe while auditing but the variables `required_validator_num` and `remove_validator` are extremely correlated and critical to the protocol. Off-chain validators would sign the parameter message hash and submit it alongside their signatures and the contract verifies it as the source of authentication. While verification the threshold number of signatures/signers must pass to consider the message to be valid which is the manager set variable `required_validator_num`

The problem is in function `remove_validator` function across both chains EVM and Starknet. Which doesn't check if it removes the validator and it could affect the `required_validators_num` Consider the following case.

Case-1: The required validator number is N and there are N+1 signers/validators whitelisted. Now if the manager removes an N-2 validator from the whitelisted any valid call would fail as the validator number would be still N and signers would be N-2. 

Also, the managers would be numerous, at a point contract could have multiple managers. So, the likelihood of it is moderate and the impact is medium/low as user funds are not at risk and it only hampers the protocol functionality until the managers either lower the `required_validators_num` or add a new validator.

### Code Links
In EVM Side

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/BaseSettlement.sol#L103-L114

In Starknet Side

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/settlement.cairo#L225-L239 

### Recommendation
Add check in `remove_validators` if the `validator count` would be less than the `required_validators_num` if the current validator is removed.
```
   function remove_validator(
        address validator
    ) external onlyRole(MANAGER_ROLE) {
        signature_verifier.remove_validator(validator);
        require(
            chakra_validators[validator] == true,
            "Validator does not exists"
        );
        chakra_validators[validator] = false;
        validator_count -= 1;
        // add this check
        require(validator_count >= required_validators_num, 'Required thresold error');
        emit ValidatorRemoved(msg.sender, validator);
    }
```
Add the similar check in the Starknet too.