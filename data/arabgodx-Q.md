# summary

1. L-01 deocde_transfer is not as documented / has a typo in the function naming. 

# code snippet

1. [poc](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ERC20CodecV1.sol#L65)

# mitigation

# summary

1. L-02 `validators[msgHash.recover(sig)] && ++m >= required_validators` can abuse required_validators if ++m double spent any validator.

# code snippet

1. [poc](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/SettlementSignatureVerifier.sol#L203)

# mitigation
