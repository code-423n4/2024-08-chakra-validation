# [QA-01] Potential Reentrancy Vulnerability in `cross_chain_erc20_settlement` Function
## Impact
TThe `cross_chain_erc20_settlement` function in the ChakraSettlementHandler contract is potentially vulnerable to reentrancy attacks. This vulnerability could allow an attacker to manipulate the contract's state, potentially leading to unauthorized token transfers, incorrect nonce management, or creation of invalid cross-chain transactions. In a worst-case scenario, this could result in financial losses or compromise the integrity of cross-chain operations.
## Proof Of Code
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L111-L224
In this function, external calls (`_erc20_lock` or `_erc20_burn`) are made before updating the contract's state (incrementing the nonce and creating a new cross-chain transaction). This order of operations violates the checks-effects-interactions pattern and leaves the function vulnerable to reentrancy attacks.
## Recommendation
Implement the checks-effects-interactions pattern by reordering the function to perform all state changes before making external calls.

# [QA-02] Public initialize function vulnerable to front-running and unauthorized initialization
## Impact
The `initialize` function in the `ChakraSettlement` contract is declared as `public`, which poses a significant security risk. This allows any external actor to call the function if it hasn't been called before, potentially initializing the contract with malicious parameters.
## Proof Of Code
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/ChakraSettlement.sol#L85-L102
The `initialize` function is declared as `public`, allowing any external address to call it. While the `initializer` modifier prevents multiple initializations, it does not prevent unauthorized initial calls.
## Recommendation
Implement access control to ensure only authorized addresses can initialize the contract.

# [QA-03] Potential DoS in Signature Verification Due to Validator Count Mismatch
## Impact
The current implementation allows `required_validators` to be set higher than `validator_count`, which can lead to a denial of service in the signature verification process. This could render the core functionality of the contract unusable and waste gas on transactions that can never succeed.
## Proof Of Code
The issue stems from the relationship between the `set_required_validators_num` function and the `verifyECDSA` function:
```
function set_required_validators_num(
    uint256 _required_validators
) external virtual onlyRole(MANAGER_ROLE) {
    uint256 old = required_validators;
    required_validators = _required_validators;
    emit RequiredValidatorsChanged(msg.sender, old, required_validators);
}

function verifyECDSA(
    bytes32 msgHash,
    bytes calldata signatures
) internal view returns (bool) {
    // ... (signature verification logic)
    for (uint256 i = 0; i < len; i += 65) {
        bytes memory sig = signatures[i:i + 65];
        if (
            validators[msgHash.recover(sig)] && ++m >= required_validators
        ) {
            return true;
        }
    }
    return false;
}
```
If `required_validators` is set higher than `validator_count`, the `verifyECDSA` function will always return `false`, regardless of the number of valid signatures provided.
## Recommendation
Add a check in the `set_required_validators_num` function to ensure `required_validators` cannot exceed `validator_count`
