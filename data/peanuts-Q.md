## Summary of Contents 

| Index | Title                                                                                                                 |
| ----- | --------------------------------------------------------------------------------------------------------------------- |
| L-01  | BaseSettlementHandler inherits AccessControlUpgradeable but doesn't use it                                            |
| L-02  | TokenRoles.sol uses UUPSUpgradeable but does not initialize it in the initializer                                     |
| L-03  | The `authorizeUpgrade()` override is not present in TokenRoles.sol                                                    |
| L-04  | There is no mention of pausing in any of the contracts                                                                |
| L-05  | Messages cannot be retried                                                                                            |
| L-06  | cross_chain_erc20_settlement in handler_erc20.cairo does not have sufficient checks unlike its solidity counterpart   |
| L-07  | Insufficient check in ChakraSettlementHandler.receive_cross_chain_msg                                                 |
| L-08  | ChakraSettlementHandler.receive_cross_chain_msg can never return false right now since only ERC20 PayloadType is used |
| L-09  | Best practice to make sure functions in settlement contracts can only be called by certain addresses                  |
| L-10  | receive_cross_chain_msg in handle_erc20.cairo will never return false                                                 |
| L-11  | Blacklisted ERC20 user can potentially have their token stuck in the contract                                         |

### [L-01] BaseSettlementHandler inherits AccessControlUpgradeable but doesn't use it

BaseSettlementHandler.sol uses AccessControlUpgradeable:

```
abstract contract BaseSettlementHandler is
    OwnableUpgradeable,
    UUPSUpgradeable,
    AccessControlUpgradeable
```

In its `init()` function, there is no `_grantRole(DEFAULT_ADMIN_ROLE, _owner);` call. AccessControlUpgradeable is inaccessible.

```
  function _Settlement_handler_init(
        address _owner,
        SettlementMode _mode,
        address _token,
        address _verifier,
        string memory _chain,
        address _settlement
    ) public {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();
        settlement = ISettlement(_settlement);
        verifier = ISettlementSignatureVerifier(_verifier);
        mode = _mode;
        token = _token;
        chain = _chain;
    }
```

Either have `_grantRole(DEFAULT_ADMIN_ROLE, _owner);` or remove AccessControlUpgradeable

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/BaseSettlementHandler.sol#L21

### [L-02] TokenRoles.sol uses UUPSUpgradeable but does not initialize it in the initializer

TokenRoles uses UUPSUpgradeable:

```
abstract contract TokenRoles is
    OwnableUpgradeable,
    UUPSUpgradeable,
    AccessControlUpgradeable
{
```

In the init function, there is no `__UUPSUpgradeable_init();` call.

```
  function __TokenRoles_init(address _owner, address _operator) public {
        __Ownable_init(_owner);
        _grantRole(DEFAULT_ADMIN_ROLE, _owner);
        _grantRole(OPERATOR_ROLE, _operator);
    }
```

Call `__UUPSUpgradeable_init()` for best practice.

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/TokenRoles.sol#L19-L23

### [L-03] The `authorizeUpgrade()` override is not present in TokenRoles.sol

Currently, the `authorizeUpgrade()` override in TokenRoles.sol is present in the inherited contracts like ChakraToken.sol and ChakraTokenUpgradeTest.sol.

```
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}
```

Best practice is to have this override in the TokenRoles.sol contract, in case any new contracts uses TokenRoles.sol but forgets to override the upgrade.

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/TokenRoles.sol#L25-L42

### [L-04] There is no mention of pausing in any of the contracts 

In the C4 docs, it states:

> Pausability (e.g. Uniswap pool gets paused),	Yes

There is no pausing capabilities in any of the contracts. If wanted, consider adding the pause mechanism to the cross-chain calls. 

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/BaseSettlement.sol#L11

### [L-05] Messages cannot be retried 

If the receiving message fails on the destination chain, the message cannot be retried since the execution status will change after the message is sent (eg Success or Failure)

For example, in receive_cross_chain_msg in ChakraSettlement.sol, the status of the tx must be `CrossChainMsgStatus.Unknow`.

```
   require(
                receive_cross_txs[txid].status == CrossChainMsgStatus.Unknow,
                "Invalid transaction status"
            );
```

If the message fails, the status will become `CrossChainMsgStatus.Failed`, and this message cannot be called again. 

```
   if (result == true) {
            status = CrossChainMsgStatus.Success;
            receive_cross_txs[txid].status = CrossChainMsgStatus.Success;
        } else {
            receive_cross_txs[txid].status = CrossChainMsgStatus.Failed;
        }
```

Consider allowing the retrying of message for convenience and to prevent any accounting errors.

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/ChakraSettlement.sol#L228

### [L-06] cross_chain_erc20_settlement in handler_erc20.cairo does not have sufficient checks unlike its solidity counterpart

In `ChakraSettlementHandler.cross_chain_erc20_settlement()`, the parameters are checked:

```
    function cross_chain_erc20_settlement(
        string memory to_chain,
        uint256 to_handler,
        uint256 to_token,
        uint256 to,
        uint256 amount
    ) external {
        require(amount > 0, "Amount must be greater than 0");
        require(to != 0, "Invalid to address");
        require(to_handler != 0, "Invalid to handler address");
        require(to_token != 0, "Invalid to token address");
```

The same check is not applied in `handler_erc20.cairo.cross_chain_erc20_settlement()`

```
      fn cross_chain_erc20_settlement(ref self: ContractState, to_chain: felt252, to_handler: u256, to_token: u256, to: u256, amount: u256) -> felt252{
            assert(self.support_handler.read((to_chain, to_handler)), 'not support handler');
            let settlement = IChakraSettlementDispatcher {contract_address: self.settlement_address.read()};
            let from_chain = settlement.chain_name();
            let token = IERC20Dispatcher{contract_address: self.token_address.read()};
            let token_burnable = IERC20MintDispatcher{contract_address: self.token_address.read()};
```

Ensure sufficient checks on the parameter of the cairo function.

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/handler_erc20.cairo#L167

### [L-07] Insufficient check in ChakraSettlementHandler.receive_cross_chain_msg

The solidity code on `ChakraSettlementHandler.receive_cross_chain_msg` checks the `from_chain` and `from_handler`, but does not check the `to_chain` and `to_handler` as well.

```
   //  from_handler need in whitelist
        if (is_valid_handler(from_chain, from_handler) == false) {
            return false;
        }
```

The cairo counterpart checks both to make sure that this chain is indeed valid and the current handler is set properly:

```
            assert(self.support_handler.read((from_chain, from_handler)) && 
                    self.support_handler.read((to_chain, contract_address_to_u256(to_handler))), 'not support handler');
```

Check both `from` and `to` in the Solidity contract. Same goes for `receive_cross_chain_callback()` 

[Cairo](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/handler_erc20.cairo#L113)
[Solidity](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L311)

### [L-08] ChakraSettlementHandler.receive_cross_chain_msg can never return false right now since only ERC20 PayloadType is used

isValidPayloadType checks that the payload_type must be ERC20

```
    function isValidPayloadType(
        PayloadType payload_type
    ) internal pure returns (bool) {
        return (payload_type == PayloadType.ERC20);
    }

```

In `receive_cross_chain_msg()`, there is a line that checks the payload_type, otherwise revert. Then, at the end of the whole function, return false.

```
   require(isValidPayloadType(payload type), "Invalid payload type");
```

Since there can only be one payload type, `receive_cross_chain_msg` will never return false.

In the future, `isValidPayloadType` should check the different payload types, instead of just ERC20

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L316

### [L-09] Best practice to make sure functions in settlement contracts can only be called by certain addresses

In ChakraSettlement.send_cross_chain_msg, the function is external, which means anybody can call the function. 

```
  function send_cross_chain_msg(
        string memory to_chain,
        address from_address,
        uint256 to_handler,
        PayloadType payload_type,
        bytes calldata payload
    ) external {
        nonce_manager[from_address] += 1;

        address from_handler = msg.sender;
```

Although the important value, `from_handler`, is made sure to be the Handler contract address, it is still best practice to have a modifier that makes sure only the Handler can call the ChakraSettlement contract, otherwise users can just call `send_cross_chain_msg()` directly to spam the messaging sequence with unauthorized message, which will affect the validators job to sieve through the messages.

Same goes for the cairo contract.

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/settlement.cairo#L284

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/ChakraSettlement.sol#L110-L123

### [L-10] receive_cross_chain_msg in handle_erc20.cairo will never return false

The whole `receive_cross_chain_msg()` only returns true, unlike its solidity counterpart where the function returns true only after a transfer, and return false otherwise.

This means that `CrossChainMsgStatus` will ever be `FAILED` since success is always true.

```
    let handler = IHandlerDispatcher{contract_address: to_handler};
            let success = handler.receive_cross_chain_msg(cross_chain_msg_id, from_chain, to_chain, from_handler, to_handler , payload);

            let mut status = CrossChainMsgStatus::SUCCESS;
            if success{
                status = CrossChainMsgStatus::SUCCESS;
            }else{
                status = CrossChainMsgStatus::FAILED;
            }

```

Ensure `receive_cross_chain_msg()` returns false as well, like how it is done in solidity ChakraSettlementHandler.sol.

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/handler_erc20.cairo#L108-L135

### [L-11] Blacklisted ERC20 user can potentially have their token stuck in the contract

If a user transferred some ERC20 tokens into the source handler contract and got some minted tokens from the destination contract, and he is suddenly blacklisted on the source chain, the user will burn his minted tokens in hopes of getting his ERC20 token back, but will be unable to do so. Tokens will be stuck in the source chain handler contract.

```
   function _safe_transfer_from(
        address from,
        address to,
        uint256 amount
    ) internal {
        require(
            IERC20(token).balanceOf(from) >= amount,
            "Insufficient balance"
        );

        // transfer tokens
        IERC20(token).transferFrom(from, to, amount);
    }
```

Consider having an onlyOwner function to change recipients, or even withdraw stuck tokens (only if cross-chain message fails can the owner be allowed to withdraw tokens to decrease centralization risks)

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L123