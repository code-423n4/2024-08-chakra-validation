
# QA Report

## Low Risk Findings
| Count | Explanation |
|:--:|:-------|
| [L-01] | `cross_chain_erc20_settlement` doesn't validated bridging to `to_chain` via `to_handler` is possible or not leading to loss of funds |
| [L-02] | Corruptible Upgradability Pattern creating issues during upgrade |
| [L-03] | Use of unsafe Transfer can lead to issues |
| [L-04] | Setting `set_required_validators_num` in Settlement doesn't update it in `SettlementSignatureVerifier` | 

| Total Low Risk Findings | 4 |
|:--:|:--:|

### [L-01] `cross_chain_erc20_settlement` doesn't validated bridging to `to_chain` via `to_handler` is possible or not leading to loss of funds

#### Bug Description

* There is no validation about `to_chain` and `to_handler` when any user call `cross_chain_erc20_settlement`.

* This can lead to User Unintensionally Locking or Burning their token for non supported handlers or chain or Previously allowed and now not allowed routes.

#### Recommendation

Validate the `to_chain` and `to_handler` to make sure that bridging is possible in that route.

### [L-02] Corruptible Upgradability Pattern creating issues during upgrade

#### Impact

Storage of `ChakraSettlementHandler`/`ChakraSettlement` contracts might be corrupted during an upgrade.

#### Bug Description

* The `ChakraSettlementHandler`/`ChakraSettlement` contracts are meant to be upgradeable. However, it inherits contracts that are not upgrade-safe like `BaseSettlementHandler` or `BaseSettlement`.

* Without gaps, adding new storage variables to any of these contracts can potentially overwrite the beginning of the storage layout of the child contract, causing critical misbehaviors in the system.

#### Recommendation

Add gaps in upgradeable parent contracts (`BaseSettlementHandler` and `BaseSettlement`) at the end of all the storage variable definitions.

### [L-03] Use of unsafe Transfer can lead to issues

#### Bug Description

* To Lock and Unlock tokens, `_safe_transfer_from` and `_safe_transfer` functions are used.

```solidity

    function _safe_transfer_from(
        address from,
        address to,
        uint256 amount
    ) internal {
        require( IERC20(token).balanceOf(from) >= amount, "Insufficient balance" );

        // transfer tokens
        IERC20(token).transferFrom(from, to, amount); // unsafe for many ERC20s
    }

    function _safe_transfer(address to, uint256 amount) internal {
        require( IERC20(token).balanceOf(address(this)) >= amount, "Insufficient balance" );

        // transfer tokens
        IERC20(token).transfer(to, amount);
    }

```

* But issue with these function is they use unsafe Transfer which can create lot of issues from variety of ERC20 tokens. 

* Eg: Some tokens do not revert on failure, but instead return false (e.g. ZRX, EURS). So for these tokens even if locking is failed it won't revert and it will still unlock tokens at destination chain.

#### Recommendation

Use Openzeppelin's `SafeERC20` for transfers.

### [L-04] Setting `set_required_validators_num` in Settlement doesn't update it in `SettlementSignatureVerifier`

#### Bug Description

* `ChakraSettlement` contract is basically manager of `SettlementSignatureVerifier` as calling function `add_validator` in `ChakraSettlement` will directly call `add_validator` in `SettlementSignatureVerifier` which has Only Manager Access.

* For Adding any validator, `add_validator` function is used while for removing any validator, `remove_validator` is used. Important to note here that it adds and removes from both Settlement and Signature contracts.

* But Setting Required number of validators in `ChakraSettlement` via `set_required_validators_num` doesn't call `set_required_validators_num` in the Signature Verifier contract.

#### Recommendation

```diff
File: BaseSettlement.sol

    function set_required_validators_num(
        uint256 _required_validators
    ) external onlyRole(MANAGER_ROLE) {
+       signature_verifier.set_required_validators_num(_required_validators);
        uint256 old = required_validators;
        required_validators = _required_validators;
        emit RequiredValidatorsChanged(msg.sender, old, required_validators);
    }

```