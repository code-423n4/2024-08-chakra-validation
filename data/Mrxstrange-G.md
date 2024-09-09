### 1. Gas Saving Report: Solidity Function Optimization

**Context:**

The original Solidity function had redundant conditional checks, leading to inefficiencies in gas usage. The goal was to streamline the logic while maintaining functionality.

**Initial Issue:**

The function repeatedly checked for different `SettlementMode` values, performing the same action (`_erc20_lock`) in three cases and a different action (`_erc20_burn`) in only one. This redundancy caused higher gas consumption.

### Optimized Implementation: ⇒ ChakraSettlementHandler.sol#L123

```solidity

if (mode == SettlementMode.BurnUnlock) {
    _erc20_burn(msg.sender, amount);
} else if (
    mode == SettlementMode.MintBurn ||
    mode == SettlementMode.LockUnlock ||
    mode == SettlementMode.LockMint
) {
    _erc20_lock(msg.sender, address(this), amount);
}

```

### Gas Savings:

- **Fewer Branches:** Reducing conditional checks from four to two saves gas on each function call.
- **Lower Bytecode Size:** Consolidating conditions reduces the bytecode size, lowering deployment costs.

### Conclusion:

This optimization trims unnecessary checks and reduces gas costs for both deployment and execution, making the function more efficient.