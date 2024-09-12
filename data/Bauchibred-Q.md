# QA Report for **Chakra**

## Table of Contents

| Issue ID                                                                                      | Description                                                                   |
| --------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| [QA-01](#qa-01-failed-transactions-should-be-retryable)                                       | Failed transactions should be retryable                                       |
| [QA-02](#qa-02-protocol-could-be-put-in-an-unwanted-state)                                    | Protocol could be put in an unwanted state                                    |
| [QA-03](#qa-03-manager-role-could-be-unintentionally-lost)                                    | Manager role could be unintentionally lost                                    |
| [QA-04](#qa-04-some-tokens-can-never-be-used-for-cross-chain-settlements)                     | Some tokens can never be used for cross chain settlements                     |
| [QA-05](#qa-05-tokens-could-get-lost-during-in-messages-or-callbacks)                         | Tokens could get lost during in messages or callbacks                         |
| [QA-06](#qa-06-no-need-to-make-use-of-hardhat-in-live-prod)                                   | No need to make use of Hardhat in live prod                                   |
| [QA-07](#qa-07-threshold-should-only-be-set-within-the-range-of-current-available-validators) | Threshold should only be set within the range of current available validators |
| [QA-08](<#qa-08-make-cross_chain_erc20_settlement()-more-efficient>)                          | Make `cross_chain_erc20_settlement()` more efficient                          |
| [QA-09](#qa-09-remove-unused-imports)                                                         | Remove unused imports                                                         |
| [QA-10](#qa-10-use-constants-instead-of-magic-numbers)                                        | Use constants instead of magic numbers                                        |
| [QA-11](#qa-11-improve-documentations-of-complex-functionalities)                             | Improve documentations of complex functionalities                             |
| [QA-12](#qa-12-remove-test-code-from-final-production)                                        | Remove test code from final production                                        |
| [QA-13](#qa-13-setters-dont-have-equality-checkers)                                           | Setters dont have equality checkers                                           |
| [QA-14](#qa-14-make-the-cairo-upgradeable-contracts-storage-logic-safe)                       | Make the Cairo upgradeable contracts storage logic safe                       |
| [QA-15](#qa-15-fix-typos)                                                                     | Fix typos                                                                     |

## QA-01 Failed transactions should be retryable

### Proof of Concept

The `receive_cross_chain_msg` function handles incoming cross-chain messages. It sets the transaction status to `Pending` after receiving the message and then calls `ISettlementHandler.receive_cross_chain_msg` to process it. The status is updated based on whether the processing succeeds or fails.

There's no retry logic implemented for failed transactions. This can lead to permanent loss of assets in certain scenarios.

**Scenario Example**:

1. User initiates a cross-chain transfer.
2. Tokens are locked in the `SettlementMode.LockUnlock` mode.
3. Reception fails due to insufficient balance.
4. Status is set to `FAILED`, but tokens remain locked.

### Impact

- Tokens could be permanently lost to both sending and receiving parties.
- Users may experience inconvenience due to stuck assets.
- The system doesn't allow for retrying failed cross-chain transfers.

### Recommended Mitigation Steps

Implement retry logic for failed cross-chain transactions or allow senders to cancel transactions on the originating chain if they fail on the receiving chain.

Citations:

## QA-02 Protocol could be put in an unwanted state

### Proof of Concept

Protocol integrates with an access control logic that restricts some functionality to the managers that can be set via `add_manager()` & `remove_manager()`.

Issue however is the fact that when removing the managers there is no check to ensure that the protocol is not left in a state where we have `0` managers, see https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/cairo/handler/src/ckr_btc.cairo#L148-L161

```cairo
        fn remove_manager(ref self: ContractState, old_manager: ContractAddress) -> bool {
            let caller = get_caller_address();
            assert(self.chakra_managers.read(caller) == 1, Errors::NOT_MANAGER);
            self.chakra_managers.write(old_manager, 0);
            self
                .emit(
                    ManagerRemoved {
                        operator: caller,
                        old_manager: old_manager,
                        removed_at: get_block_timestamp()
                    }
                );
            return self.chakra_managers.read(old_manager) == 0;
        }
```

### Impact

Core functionalities would be unreachable, considering functions like [adding/removing operators require the callers to be managers](https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/cairo/handler/src/ckr_btc.cairo#L169-L193), so in a case we have no managers at all, no new managers can be set due to this [check](https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/cairo/handler/src/ckr_btc.cairo#L136).

### Recommended Mitigation Steps

Consider including a check when removing a manager that there is atleast one more managers existing.

## QA-03 Manager role could be unintentionally lost

### Proof of Concept

Take a look at https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/cairo/handler/src/ckr_btc.cairo#L134-L147

```cairo
        fn add_manager(ref self: ContractState, new_manager: ContractAddress) -> bool {
            let caller = get_caller_address();
            assert(self.chakra_managers.read(caller) == 1, Errors::NOT_MANAGER);
            assert(self.chakra_managers.read(new_manager) == 0, Errors::ALREADY_MANAGER);

            self.chakra_managers.write(new_manager, 1);
            self
                .emit(
                    ManagerAdded {
                        operator: caller, new_manager: new_manager, added_at: get_block_timestamp()
                    }
                );
            return self.chakra_managers.read(new_manager) == 1;
        }
```

This is the functionality used to remove an admin, evidently this is done in one step.

Issue however is if the new manager's `ContractAddress` was wrongly set then the role is completely lost, considering the admin change is done in one step and in a push not pull manner.

### Impact

Permanent loss of the manager role

### Recommended Mitigation Steps

Transfer managers using two steps and have the new manager come claim their role.

## QA-04 Some tokens can never be used for cross chain settlements

### Proof of Concept

Depending on the [current settlement mode,](https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/solidity/handler/contracts/ChakraSettlementHandler.sol#L122-L131) there are a few internal methods that can be queried when settling erc20s cross chain,

IN whatever case though there would be a need to transfer these tokens via: https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/solidity/handler/contracts/ChakraSettlementHandler.sol#L256-L269

```solidity

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

        function _safe_transfer(address to, uint256 amount) internal {
        require(
            IERC20(token).balanceOf(address(this)) >= amount,
            "Insufficient balance"
        );

        // transfer tokens
        IERC20(token).transfer(to, amount);
    }
```

Issue however is the fact that protocol assumes all `erc20s` support the `IERC20(token).balanceOf()` functionality, this however is a wrong believe which causes this implementation to always revert for some tokens like Aura's stash tokens which do not implement the `balanceOf()` functionality.

### Impact

DOS to any flow that queries `_safe_transfer_from()` for these set of tokens, inclusive and not exclusive of the cross chain settlements

### Recommended Mitigation Steps

Consider querying the balance of on a low level.

## QA-05 Tokens could get lost during in messages or callbacks

### Proof of Concept

Take a look at https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/cairo/handler/src/ckr_btc.cairo#L199-L207

```cairo
        fn mint_to(ref self: ContractState, to: ContractAddress, amount: u256) -> bool {
            let caller = get_caller_address();
            assert(self.chakra_operators.read(caller) == 1, Errors::NOT_OPERATOR);
            let old_balance = self.erc20.balance_of(to);
            self.erc20.mint(to, amount);
            let new_balance = self.erc20.balance_of(to);
            return new_balance == old_balance + amount;
        }

```

Evidently, during mints there are no checks that the receiver is not the `0`, address, this is quite rampant in scope, which tne means that tokens could get lost.

### Impact

QA, needs to be admin/user error.

### Recommended Mitigation Steps

Include a check that tokens can't get directly minted to the `0x0` or `0xdead` address.

## QA-06 No need to make use of Hardhat in live prod

### Proof of Concept

Take a look at https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/solidity/handler/contracts/ChakraSettlementHandler.sol#L1-L18

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "hardhat/console.sol"; //@audit

import {ISettlement} from "contracts/interfaces/ISettlement.sol";
import {IERC20CodecV1} from "contracts/interfaces/IERC20CodecV1.sol";
import {IERC20Mint} from "contracts/interfaces/IERC20Mint.sol";
import {IERC20Burn} from "contracts/interfaces/IERC20Burn.sol";
import {ISettlementHandler} from "contracts/interfaces/ISettlementHandler.sol";
import {AddressCast} from "contracts/libraries/AddressCast.sol";
import {Message, PayloadType, CrossChainMsgStatus} from "contracts/libraries/Message.sol";
import {MessageV1Codec} from "contracts/libraries/MessageV1Codec.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {BaseSettlementHandler} from "contracts/BaseSettlementHandler.sol";
import "contracts/libraries/ERC20Payload.sol";

contract ChakraSettlementHandler is BaseSettlementHandler, ISettlementHandler {
```

Evidently there is an unnecessary importation of hardhat being done

### Impact

QA

### Recommended Mitigation Steps

Apply these changes:

```diff
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

-import "hardhat/console.sol";

..snip
```

## QA-07 Threshold should only be set within the range of current available validators

### Proof of Concept

Take a look at https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/solidity/handler/contracts/SettlementSignatureVerifier.sol#L92-L99

```solidity
    function set_required_validators_num(
        uint256 _required_validators
    ) external virtual onlyRole(MANAGER_ROLE) {
        uint256 old = required_validators;
        required_validators = _required_validators;
        emit RequiredValidatorsChanged(msg.sender, old, required_validators);
    }

```

This function is used to set the required amount of validators that need to sign [before the signature verification process passes](https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/solidity/handler/contracts/SettlementSignatureVerifier.sol#L120-L141) issue however is the fact that this value is being set without any check to ensure its always less than the validator count value.

### Impact

If the `required_validators` is set to a value higher than the validator count value, then no verification can be successful, since it always returns false [here](https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/solidity/handler/contracts/SettlementSignatureVerifier.sol#L140).

### Recommended Mitigation Steps

Apply these changes:

```diff
    function set_required_validators_num(
        uint256 _required_validators
    ) external virtual onlyRole(MANAGER_ROLE) {
+       require( _required_validators <= validator_count, "Threshold must be less than validator count");
        uint256 old = required_validators;
        required_validators = _required_validators;
        emit RequiredValidatorsChanged(msg.sender, old, required_validators);
    }

```

## QA-08 Make `cross_chain_erc20_settlement()` more efficient

### Proof of Concept

Take a look at https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/cairo/handler/src/handler_erc20.cairo#L167-L232

```cairo
        fn cross_chain_erc20_settlement(ref self: ContractState, to_chain: felt252, to_handler: u256, to_token: u256, to: u256, amount: u256) -> felt252{
            assert(self.support_handler.read((to_chain, to_handler)), 'not support handler');
            let settlement = IChakraSettlementDispatcher {contract_address: self.settlement_address.read()};
            let from_chain = settlement.chain_name();
            let token = IERC20Dispatcher{contract_address: self.token_address.read()};
            let token_burnable = IERC20MintDispatcher{contract_address: self.token_address.read()};
            let mode = self.mode.read();
            let caller = get_caller_address();
            let contract_addr = get_contract_address();

            if mode == SettlementMode::MintBurn{
                token.transfer_from(caller, contract_addr, amount);
            }else if mode == SettlementMode::LockMint{
                token.transfer_from(caller, contract_addr, amount);
            }else if mode == SettlementMode::BurnUnlock{
                token_burnable.burn_from(caller, amount);
            }else if mode == SettlementMode::LockUnlock{
                token.transfer_from(caller, contract_addr, amount);
            }

   //snip
            return tx_id;
        }
```

Make this more efficient by storing the contract address in stead of querying it three times: I.e read all of self.mode.read(), get_caller_address(), get_contract_address() once outside the if/else if checks store them and then use these values in the checks

### Impact

QA

### Recommended Mitigation Steps

Apply the suggested fix, pseudo fix:

```cairo
     fn cross_chain_erc20_settlement(ref self: ContractState, to_chain: felt252, to_handler: u256, to_token: u256, to: u256, amount: u256) -> felt252{
         assert(self.support_handler.read((to_chain, to_handler)), 'not support handler');
         let settlement = IChakraSettlementDispatcher {contract_address: self.settlement_address.read()};
         let from_chain = settlement.chain_name();
         let token = IERC20Dispatcher{contract_address: self.token_address.read()};
         let token_burnable = IERC20MintDispatcher{contract_address: self.token_address.read()};

         // Store values outside the if/else checks
         let mode = self.mode.read();
         let caller = get_caller_address();
         let contract_addr = get_contract_address();

         if mode == SettlementMode::MintBurn{
             token.transfer_from(caller, contract_addr, amount);
         }else if mode == SettlementMode::LockMint{
             token.transfer_from(caller, contract_addr, amount);
         }else if mode == SettlementMode::BurnUnlock{
             token_burnable.burn_from(caller, amount);
         }else if mode == SettlementMode::LockUnlock{
             token.transfer_from(caller, contract_addr, amount);
         }

//snip
         return tx_id;
     }

```

## QA-09 Remove unused imports

### Proof of Concept

Take a look at https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/solidity/handler/contracts/SettlementSignatureVerifier.sol#L7-L8

```solidity
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

```

This is part of the `SettlementSignatureVerifier.sol` contract where we have an importation of the hashing utils, issue however is that going through the whole contract and it's verification logic, we can see that there is no instance where this is being used in the contract.

### Impact

QA

### Recommended Mitigation Steps

Use or remove the import.

## QA-10 Use constants instead of magic numbers

### Proof of Concept

This is pertaining to the whole [utils.cairo](https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/cairo/handler/src/utils.cairo) contract, in most cases we see magic numbers like `0x100` however this can be made better by using constants instead.

### Impact

QA complicates the flow for auditors/users and devs.

### Recommended Mitigation Steps

Improve documentation.

## QA-11 Improve documentations of complex functionalities

### Proof of Concept

This is pertaining to the whole [utils.cairo](https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/cairo/handler/src/utils.cairo) contract, it completely lacks any documentation whereas all the functionalities are not as easy as they come.

### Impact

QA complicates the flow for auditors/users and devs

### Recommended Mitigation Steps

Improve documentation.

## QA-12 Remove test code from final production

### Proof of Concept

Take a look at https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/solidity/handler/contracts/SettlementSignatureVerifier.sol#L30-L31

```solidity

    event Test(address validator);
```

The snippet above is used for testing purposes but is still left in live production.

### Impact

QA

### Recommended Mitigation Steps

Remove the event

## QA-13 Setters dont have equality checkers

### Proof of Concept

Take a look at https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/cairo/handler/src/ckr_btc.cairo#L148-L162

```cairo
        fn remove_manager(ref self: ContractState, old_manager: ContractAddress) -> bool {
            let caller = get_caller_address();
            assert(self.chakra_managers.read(caller) == 1, Errors::NOT_MANAGER);
            self.chakra_managers.write(old_manager, 0);
            self
                .emit(
                    ManagerRemoved {
                        operator: caller,
                        old_manager: old_manager,
                        removed_at: get_block_timestamp()
                    }
                );
            return self.chakra_managers.read(old_manager) == 0;
        }

```

This functionality is used to remove a manager, however it has no check that the `old_manager` written permission is not `0`

### Impact

QA

### Recommended Mitigation Steps

Apply these changes

```diff
        fn remove_manager(ref self: ContractState, old_manager: ContractAddress) -> bool {
            let caller = get_caller_address();
            assert(self.chakra_managers.read(caller) == 1, Errors::NOT_MANAGER);
+            assert(self.chakra_managers.read(new_manager) == 1, Errors::NOT_MANAGER);
            self.chakra_managers.write(old_manager, 0);
            self
                .emit(
                    ManagerRemoved {
                        operator: caller,
                        old_manager: old_manager,
                        removed_at: get_block_timestamp()
                    }
                );
            return self.chakra_managers.read(old_manager) == 0;
        }

```

This is also what's done, rightfully so when removing operators: see https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/cairo/handler/src/ckr_btc.cairo#L181-L186

```cairo
        fn remove_operator(ref self: ContractState, old_operator: ContractAddress) -> bool {
            let caller = get_caller_address();
            assert(self.chakra_managers.read(caller) == 1, Errors::NOT_MANAGER);
            assert(self.chakra_operators.read(old_operator) == 1, Errors::NOT_OPERATOR);/@audit
            self.chakra_operators.write(old_operator, 0);
            self

            //snip

        }
```

## QA-14 Make the Cairo upgradeable contracts storage logic safe

### Proof of Concept

Multiple instances all over theCairo contracts scope, but take a look at https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/cairo/handler/src/settlement.cairo#L52-L72

```cairo
    #[storage]
    struct Storage {
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        #[substorage(v0)]
        upgradeable: UpgradeableComponent::Storage,
        // storage the pubkeys as validator
        chakra_validators_pubkey: LegacyMap<felt252, u8>,
        // storage manager
        chakra_managers: LegacyMap<ContractAddress, u8>,
        // storage the txs which received
        received_tx:LegacyMap<u256, ReceivedTx>,
        // storage the txs which created
        created_tx:LegacyMap<felt252, CreatedTx>,
        // deployed chain name
        chain_name:felt252,
        // the number of verified signature
        required_validators_num: u32,
        // transaction count
        tx_count: u256
    }
```

This is the storage logic for the upgradeable settlement contract, however it lacks any gaps logic which leaves it's upgradeability unsafe, see [this](https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps) for more info.

### Impact

QA - best practice

### Recommended Mitigation Steps

Include some sort of gaps.

## QA-15 Fix typos

### Proof of Concept

Take a look at https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/solidity/handler/contracts/libraries/Message.sol#L24-L30

```solidity
enum CrossChainMsgStatus {
    Unknow,
    Pending,
    Success,
    Failed
}

```

Also https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/solidity/settlement/contracts/ChakraSettlement.sol#L198-L203

```solidity

            require(
                receive_cross_txs[txid].status == CrossChainMsgStatus.Unknow,
                "Invalid transaction status"
            );
        }
```

- https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/solidity/handler/contracts/BaseSettlementHandler.sol#L23-L30

```solidity
    enum CrossChainTxStatus {
        Unknow,
        Pending,
        Minted,
        Settled,
        Failed
    }

```

https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/solidity/handler/contracts/BaseSettlementHandler.sol#L100-L105

```solidity
    enum HandlerStatus {
        Unknow,
        Pending,
        Success,
        Failed
    }
```

`Unknow` should be `Unknown` instead.

- https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/solidity/handler/contracts/SettlementSignatureVerifier.sol#L32-L36

```solidity
    /**
     * @notice The MANAGER_ROLE indicats that only this only can be call add_validator and remove_validator.
     */
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");

```

`indicats` change to `indicates`.

- Also here: https://github.com/code-423n4/2024-08-chakra/blob/abef77d95866f2fec93270491fc5abc9ab14f86d/cairo/handler/src/settlement.cairo#L195-L202

```cairo
        // @notice change the number of reqire validators, only manager can call this function
        // @param new_num the number of reqire validators
        fn set_required_validators_num(ref self: ContractState, new_num: u32) -> u32 {
            let caller = get_caller_address();
            assert(self.chakra_managers.read(caller) == 1, 'Caller is not a manager');
            self.required_validators_num.write(new_num);
            return self.required_validators_num.read();
        }
```

Both instances of `reqire` should be `require` instead.

### Impact

QA

### Recommended Mitigation Steps

Apply the fixes
