1. Missing Validation for `to_chain` Parameter in `cross_chain_erc20_settlement`: Users can call cross_chain_erc20_settlement with empty or null to_chain. All other input params are being checked for non-zero values.
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L118-L121


2. Inconsistent Validator Management: The `add_validator` and `remove_validator` functions in BaseSettlement interact with the signature_verifier, but `set_required_validators_num` does not update the verifier, creating an inconsistency in how validator-related state is managed across contracts and potentially causing partial updates to config.
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/BaseSettlement.sol#L88-L126


3. The ReceivedCrossChainTx struct is incorrectly updating the to_handler field with address(this) instead of the actual to_handler parameter.https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/ChakraSettlement.sol#L211