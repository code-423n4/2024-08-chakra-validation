## [L-01] lack of `__AccessControl_init` in upgradable init function
FILE:
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/BaseSettlementHandler.sol#L113-L128
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/SettlementSignatureVerifier.sol#L47-L56
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/BaseSettlement.sol#L54-L74
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/SettlementSignatureVerifier.sol#L58-L67

While the upgradable contracts inherit from openzeppelin's `AccessControlUpgradeable` contract, `__AccessControl_init` should be called.

## [L-02] `ChakraSettlementHandler._safe_transfer_from` should check the allowance
FILE:
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L257-L269

In [ChakraSettlementHandler.sol#L262-L265], the balance is checked before calling `IERC20(token).transferFrom`, it's better to check allowance before calling `IERC20(token).transferFrom`

## [L-03] Tokens with a maximum transfer logic could cause accounting issues
FILE:
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L111-L223

Tokens with the special condition of doing a full balance transfer when transferring amount == type(uint256).max (most notably [cUSDCv3](https://optimistic.etherscan.io/token/0x2e44e174f7D53F0212823acC11C01A11d58c5bCB?a=0x2a376410fd9e5546bcce9f5bdabeb5b8ad8d09de#code)) have the potential to brick accounting in edge-case portfolios or be weaponized by malicious managers.
```solidity
    function transferInternal(address operator, address src, address dst, address asset, uint amount) internal {
        if (isTransferPaused()) revert Paused();
        if (!hasPermission(src, operator)) revert Unauthorized();
        if (src == dst) revert NoSelfTransfer();

        if (asset == baseToken) {
            if (amount == type(uint256).max) { <<<--- if type(unit).max is used, balanceOf(src) will be used
                amount = balanceOf(src);
            }
            return transferBase(src, dst, amount);
        } else {
            return transferCollateral(src, dst, asset, safe128(amount));
        }
    }
```

So if the user fill `amount` with `type(uint).max`, on src chain, the balanceOf(msg.sender) will be locked, and on the dest chain, the `balanceOf(token_handler)` will be transferred to the user.

## [L-04] incorrect event data in `ChakraSettlementHandler.CreatedCrossChainTx`
File:
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L160
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L218
According to `CreatedCrossChainTx`'s [defination](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/BaseSettlementHandler.sol#L53-L63), the value in [ChakraSettlementHandler.sol#L160](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L160) should be `from_token`, which should be **token**, instead of `address(this)`, which means `from_handle`
Same issue happends in [ChakraSettlementHandler.sol#L218](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L218)


## [L-05] function `ChakraSettlementHandler.receive_cross_chain_msg` should check `Message.id`
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L316

In [ChakraSettlementHandler.receive_cross_chain_msg](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L299-L355), the function only checks [payloadType](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L316), and not check if `Message.id` equals to `ERC20Method.Transfer`. which doesn't consistent with cairo code [handler_erc20.cairo#L122](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/handler_erc20.cairo#L122)

## [L-06] `TokenRoles.__TokenRoles_init` implementation has multiple issues.
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/TokenRoles.sol#L19-L23

1. `TokenRoles.__TokenRoles_init` inherits from `UUPSUpgradeable` and `AccessControlUpgradeable`, but the function doesn't call `__UUPSUpgradeable_init` and `__AccessControl_init`
1. it's better to use **internal onlyInitializing** instead of **public** as modifier
```sodlidity
 17     function __TokenRoles_init(address _owner, address _operator) public {
 18         __Ownable_init(_owner);
 19         _grantRole(DEFAULT_ADMIN_ROLE, _owner);
 20         _grantRole(OPERATOR_ROLE, _operator);
 21     }
```

## [L-07] `ckr_btc.add_manager` and `ckr_btc.remove_manager` should be called by owner, instead of `chakra_managers`
FILE:
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/ckr_btc.cairo#L134-L161

To consistent with [BaseSettlement](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/BaseSettlement.sol#L149-L162) and [SettlementSignatureVerifier](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/SettlementSignatureVerifier.sol#L83-L96), `ckr_btc.add_manager` and `ckr_btc.remove_manager` should be called by owner, instead of `chakra_managers`

## [L-08] `ckr_btc.remove_manager` doesn't check if `old_manager` exists in `self.chakra_managers`
FILE:
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/ckr_btc.cairo#L148-L160

Unlike other [ckr_btc.remove_operator](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/ckr_btc.cairo#L181-L193), the `ckr_btc.remove_manager` doesn't check if `old_manager` exists in `self.chakra_managers`

## [L-09] `handler_erc20.cross_chain_erc20_settlement` should check if `amount` > 0
FILE:
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/handler_erc20.cairo#L166-L232

According to [main invariants](https://github.com/code-423n4/2024-08-chakra/tree/main?tab=readme-ov-file#main-invariants):
>Cross-chain ERC20 settlements can only be initiated with a valid amount (greater than 0), a valid recipient address, a valid handler address, and a valid token address.

so `handler_erc20.cross_chain_erc20_settlement` should check if `amount` > 0

## [L-10] incorrect value used in `CreatedCrossChainTx`
FILE:
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/handler_erc20.cairo#L188

According to `CreatedCrossChainTx`'s defination, [from](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/handler_erc20.cairo#L98) shoulde be the tx caller, which is `get_caller_address` instead of `get_contract_address`

## [L-11] `tx_id` is generated by different algorithm in cairo and solidity
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/handler_erc20.cairo#L183-L194
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/handler_erc20.cairo#L198-L206
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/settlement.cairo#L289

`tx_id` is generated by different algorithm in cairo and solidity

## [L-12] `handler_erc20.CrossChainLocked` missing `mode` member
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/handler_erc20.cairo#L79-L91
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/BaseSettlementHandler.sol#L41-L51

`BaseSettlementHandler.CrossChainLocked` has a member called [mode](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/BaseSettlementHandler.sol#L50), and [handler_erc20.CrossChainLocked](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/handler_erc20.cairo#L79-L91) doesn't have

