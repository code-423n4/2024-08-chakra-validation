1. Missing Validation for `to_chain` Parameter in `cross_chain_erc20_settlement`: Users can call cross_chain_erc20_settlement with empty or null to_chain. All other input params are being checked for non-zero values.
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L118-L121


2. Inconsistent Validator Management: The `add_validator` and `remove_validator` functions in BaseSettlement interact with the signature_verifier, but `set_required_validators_num` does not update the verifier, creating an inconsistency in how validator-related state is managed across contracts and potentially causing partial updates to config.
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/BaseSettlement.sol#L88-L126


3. The ReceivedCrossChainTx struct is incorrectly updating the to_handler field with address(this) instead of the actual to_handler parameter.https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/ChakraSettlement.sol#L211


4. The BurnUnlock and LockMint modes in the ChakraSettlementHandler contract allow for unconstrained changes to the token supply across chains. In BurnUnlock mode, tokens are burned on the source chain (_erc20_burn(msg.sender, amount)) and unlocked on the destination chain (_erc20_unlock(AddressCast.to_address(transfer_payload.to), transfer_payload.amount)), decreasing their total supply across chains. Conversely, in LockMint mode, tokens are locked on the source chain (_erc20_lock(msg.sender, address(this), amount)) and minted on the destination chain (_erc20_mint(AddressCast.to_address(transfer_payload.to), transfer_payload.amount)). These operations lack any supply caps or rate limiting mechanisms, potentially leading to significant and uncontrolled alterations in the total token supply across all connected chains.Example ref: 
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L340 and https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L128 for LockMint case