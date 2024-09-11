| Count | Title |
| --- | --- |
| [QA-01](#qa-01-basesettlement-should-update-required_validators-in-settlementsignatureverifier) | `BaseSettlement` should update `required_validators` in `SettlementSignatureVerifier` |
| [QA-02](#qa-02-createdcrosschaintx-contains-wrong-token) | `CreatedCrossChainTx` contains wrong `token` |
| [QA-03](#qa-03-config-on-starknet-allows-calling-for-to_chain-and-to_handler-at-the-same-chain) | config on Starknet allows calling for to_chain and to_handler at the same chain |
| [QA-04](#qa-04-wrong-address-passed-as-createdcrosschaintxfrom-in-cross_chain_erc20_settlement) | Wrong address passed as `CreatedCrossChainTx.from` in `cross_chain_erc20_settlement` |
| [QA-05](#qa-05-receive_cross_chain_msg-has-no-access-control-users-can-grief-validators-with-frontrun) | `receive_cross_chain_msg` has no access control, users can grief validators with frontrun |
| [QA-06](#qa-06-missing-check-if-the-txid-exists-in-created_tx) | Missing check if the `txid` exists in `created_tx` |
| [QA-07](#qa-07-erc20transferpayload-encodingdecoding-can-be-simplified) | `ERC20TransferPayload` encoding/decoding can be simplified |
| [QA-08](#qa-08-superfluous-checks-in-receive_cross_chain_msg) | superfluous checks in `receive_cross_chain_msg` |
| [QA-09](#qa-09-receive_cross_chain_msg-has-unnecessary-if-clause) | `receive_cross_chain_msg` has unnecessary if clause |
| [QA-10](#qa-10-verifyecdsa-can-have-strict-equality) | `verifyECDSA` can have strict equality |
| [QA-11](#qa-11-cross_chain_erc20_settlement-is-missing-address-0-check-in-cairo) | `cross_chain_erc20_settlement` is missing address 0 check in Cairo |
| [QA-12](#qa-12-cross_chain_erc20_settlement-is-missing-zero-amount-check) | `cross_chain_erc20_settlement` is missing zero amount check in Cairo |
| [QA-13](#qa-13-set_required_validators_num-should-have-check-if-req_validator--validator_count) | `set_required_validators_num` should have check if `req_validator` < `validator_count` |
| [QA-14](#qa-14-missing-disableinitializers-in-settlementsignatureverifier) | missing `dissableInitializers` in `SettlementSignatureVerifier` |
| [QA-15](#qa-15-txid-is-generated-differently-on-starknet) | `txId` is generated differently on Starknet |
| [QA-16](#qa-16-messageid-wrongly-downcasted-to-uint64) | `Message.id` wrongly downcasted to `uint64` |
| [QA-17](#qa-17-whole-system-is-missing-pausability) | Whole system is missing pausability |
| [QA-18](#qa-18-cross-chain-txs-always-revert-in-case-are-invalid-instead-of-setting-status--failed) | Cross-chain txs always revert in case are invalid, instead of setting status = `FAILED` |
| [QA-19](#qa-19-wrong-message_hash-in-receive_cross_chain_msg-on--starknet-compared-to-evm) | Wrong message_hash in `receive_cross_chain_msg` on  Starknet compared to EVM |
| [QA-20](#qa-20-wrong-message_hash-in-receive_cross_chain_callback-on-starknet-compared-to-evm) | Wrong message_hash in `receive_cross_chain_callback` on Starknet compared to EVM |
| [QA-21](#qa-21-protocol-hashes-do-not-use-eip712) | Protocol hashes do not use EIP712 |

| Total Issues | 21 |
| --- | --- |

## [QA-01] `BaseSettlement` should update `required_validators` in `SettlementSignatureVerifier`

**Issue Description:**

BaseSettlement adds validators to `signature_verifier`(`SettlementSignatureVerifier`) through functions inside BaseSettlement. When a required_validators is updated inside BaseSettlement it must update the required_validators inside `signature_verifier`(`SettlementSignatureVerifier`) also since they are the used ones.

[BaseSettlement.sol](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/BaseSettlement.sol#L121-L128)

```solidity
BaseSettlement.sol

function set_required_validators_num(
    uint256 _required_validators
) external onlyRole(MANAGER_ROLE) {
    uint256 old = required_validators;
    required_validators = _required_validators;
    emit RequiredValidatorsChanged(msg.sender, old, required_validators);
}

```

**Recommendation:**

```diff
function set_required_validators_num(
    uint256 _required_validators
) external onlyRole(MANAGER_ROLE) {
    uint256 old = required_validators;
    required_validators = _required_validators;
+   signature_verifier.set_required_validators_num(_required_validators);
    emit RequiredValidatorsChanged(msg.sender, old, required_validators);
}

```

## [QA-02] `CreatedCrossChainTx` contains wrong `token`

**Issue Description:**

`CreatedCrossChainTx` struct record, created in `ChakraSettlementHandler::cross_chain_erc20_settlement` uses `address(this)` instead of `token` of the Handler. If we take a look at the struct:

[ChakraSettlementHandler.sol](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/ChakraSettlementHandler.sol#L145)

```solidity
struct CreatedCrossChainTx {
      uint256 txid;
      string from_chain;
      string to_chain;
      address from;
      uint256 to;
      address from_token;
      uint256 to_token;
      uint256 amount;
      CrossChainTxStatus status;
  }
```

we will see that the 6th param is named `from_token`, and then in `cross_chain_erc20_settlement`:

```solidity
create_cross_txs[txid] = CreatedCrossChainTx(
          txid,
          chain,
          to_chain,
          msg.sender,
          to,
          address(this),//6th param
          to_token,
          amount,
          CrossChainTxStatus.Pending
      );
```

While this struct is not used in either one of the functions later, the `receive_cross_chain_callback` uses the storage variable and doesn’t rely on the param from the struct.

**Recommendation:**

Use the `token` storage variable instead of `address(this)`:

```diff
create_cross_txs[txid] = CreatedCrossChainTx(
          txid,
          chain,
          to_chain,
          msg.sender,
          to,
-         address(this),
+         token, 
          to_token,
          amount,
          CrossChainTxStatus.Pending
      );
```

## [QA-03] config on `Starknet` allows calling for `to_chain` and `to_handler` at the same chain

**Issue Description:**

Looking at the assert statement in `handler_erc20::receive_cross_chain_callback` we can see that `to_handler` and `to_chain` are also validated to be in the `support_handler` collection:

[handler_erc20.cairo](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/handler_erc20.cairo#L144-L145)

```rust

  assert(self.support_handler.read((from_chain, from_handler)) && 
  self.support_handler.read((to_chain, contract_address_to_u256(to_handler))), 'not support handler');
```

In reality these 2 should be the same address and same chain on which the execution is happening. Knowing that users can create cross chain transactions for the same chain and spam validators with transactions:

[handler_erc20.cairo](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/handler_erc20.cairo#L168)

```rust
fn cross_chain_erc20_settlement(ref self: ContractState, to_chain: felt252, to_handler: u256, to_token: u256, to: u256, amount: u256) -> felt252{
          assert(self.support_handler.read((to_chain, to_handler)), 'not support handler');
```

The assert in `cross_chain_erc20_settlement` is intended to validate whether the destination is supported but because of the check above the admin is forced to add the address and chain of the contract that is calling the `cross_chain_erc20_settlement` function.

**Recommendation:**

Simplify the assert in `receive_cross_chain_callback` and `receive_cross_chain_callback` by removing `to_chain` and `to_handler`.

```diff

-  assert(self.support_handler.read((from_chain, from_handler)) && self.support_handler.read((to_chain, contract_address_to_u256(to_handler))), 'not support handler');
+  assert(self.support_handler.read((from_chain, from_handler))), 'not support handler');

```

## [QA-04] Wrong address passed as `CreatedCrossChainTx.from` in `cross_chain_erc20_settlement`

**Issue Description:**

in `handler_erc20::cross_chain_erc20_settlement` when `CreatedCrossChainTx` is created, the code wrongly assign `get_contract_address` instead of `get_caller_address` as from address:

[handler_erc20.cairo](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/handler_erc20.cairo#L188)

```rust
let tx: CreatedCrossChainTx = CreatedCrossChainTx{
    tx_id: tx_id,
    from_chain: from_chain,
    to_chain: to_chain,
    from: get_contract_address(),//this one should be get_caller_address instead
    to: to,
    from_token: self.token_address.read(),
    to_token: to_token,
    amount: amount,
    tx_status: CrossChainTxStatus::PENDING
};
```

Although this struct to not be used in any important functions it will still show wrong data and can confuse users of Chakra.

**Recommendation:**

Replace `get_contract_address` with `get_caller_address` in `handler_erc20::cross_chain_erc20_settlement`:

```diff
fn cross_chain_erc20_settlement(ref self: ContractState, to_chain: felt252, to_handler: u256, to_token: u256, to: u256, amount: u256) -> felt252{
    assert(self.support_handler.read((to_chain, to_handler)), 'not support handler');
    let settlement = IChakraSettlementDispatcher {contract_address: self.settlement_address.read()};
    let from_chain = settlement.chain_name();
    let token = IERC20Dispatcher{contract_address: self.token_address.read()};
    let token_burnable = IERC20MintDispatcher{contract_address: self.token_address.read()};
    if self.mode.read() == SettlementMode::MintBurn{
        token.transfer_from(get_caller_address(), get_contract_address(), amount);
    }else if self.mode.read() == SettlementMode::LockMint{
        token.transfer_from(get_caller_address(), get_contract_address(), amount);
    }else if self.mode.read() == SettlementMode::BurnUnlock{
        token_burnable.burn_from(get_caller_address(), amount);
    }else if self.mode.read() == SettlementMode::LockUnlock{
        token.transfer_from(get_caller_address(), get_contract_address(), amount);
    }
    
    let tx_id = LegacyHash::hash(get_tx_info().unbox().transaction_hash, self.msg_count.read());
    let tx: CreatedCrossChainTx = CreatedCrossChainTx{
            tx_id: tx_id,
            from_chain: from_chain,
            to_chain: to_chain,
-           from: get_contract_address(),
+           from: get_caller_address(),
            to: to,
            from_token: self.token_address.read(),
            to_token: to_token,
            amount: amount,
            tx_status: CrossChainTxStatus::PENDING
        };
```

## [QA-05] `receive_cross_chain_msg` has no access control, users can grief validators with frontrun

**Issue Description:**

`receive_cross_chain_msg` in both `ChakraSettlement` (Solidity) and `settlement` (Cairo) are missing access control and allow anyone, observing the mempool, to steal the signatures and frontrun the messages gas griefing the trusted entities that should call this function:

[ChakraSettlement.sol](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L170C5-L197C15)

```solidity
function receive_cross_chain_msg(
        uint256 txid,
        string memory from_chain,
        uint256 from_address,
        uint256 from_handler,
        address to_handler,
        PayloadType payload_type,
        bytes calldata payload,
        uint8 sign_type, // validators signature type /  multisig or bls sr25519
        bytes calldata signatures // signature array
    ) external {
        {
            // verify signature
            bytes32 message_hash = keccak256(
                abi.encodePacked(
                    txid,
                    from_chain,
                    from_address,
                    from_handler,
                    to_handler,
                    keccak256(payload)
                )
            );

            require(
                signature_verifier.verify(message_hash, signatures, sign_type),
                "Invalid signature"
            );
```

[settlement.cairo](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L325-L350)

```rust
fn receive_cross_chain_msg(
            ref self: ContractState,
            cross_chain_msg_id: u256,
            from_chain: felt252,
            to_chain: felt252,
            from_handler: u256,
            to_handler: ContractAddress,
            sign_type: u8,
            signatures: Array<(felt252, felt252, bool)>,
            payload: Array<u8>,
            payload_type: u8,
        ) -> bool {
            assert(to_chain == self.chain_name.read(), 'error to_chain');

            // verify signatures
            let mut message_hash: felt252 = LegacyHash::hash(from_chain, (cross_chain_msg_id, to_chain, from_handler, to_handler));
            let payload_span = payload.span();
            let mut i = 0;
            loop {
                if i > payload_span.len()-1{
                    break;
                }
                message_hash = LegacyHash::hash(message_hash, * payload_span.at(i));
                i += 1;
            };
            self.check_chakra_signatures(message_hash, signatures);
```

As we can see nowhere caller validation is done, only signatures are checked whether they belong to the current validators.

The grief is basically as ERC20 permit frontrunning, explained [here](https://www.trust-security.xyz/post/permission-denied). Although no harm is done it affects the honest actors.

**Recommendation:**

Add access-control allowing only Chakra trusted entities to call these functions.

## [QA-06] Missing check if the `txid` exists in `created_tx`

**Issue Description:**

`receive_cross_chain_callback` in Cairo and the one in Solidity aren’t the same as logic, since the one in Cairo is missing a crucial check ensuring `txId` is created.

[ChakraSettlementHandler.sol#L365-L396](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/ChakraSettlementHandler.sol#L365-L396)

```solidity
function receive_cross_chain_callback(
    uint256 txid,
    string memory from_chain,
    uint256 from_handler,
    CrossChainMsgStatus status,
    uint8 /* sign_type */, // validators signature type /  multisig or bls sr25519
    bytes calldata /* signatures */
) external onlySettlement returns (bool) {
    //  from_handler need in whitelist
    if (is_valid_handler(from_chain, from_handler) == false) {
        return false;
    }

    require(
        create_cross_txs[txid].status == CrossChainTxStatus.Pending,  <--------------------------------
        "invalid CrossChainTxStatus"
    );

    if (status == CrossChainMsgStatus.Success) {
        if (mode == SettlementMode.MintBurn) {
            _erc20_burn(address(this), create_cross_txs[txid].amount);
        }

        create_cross_txs[txid].status = CrossChainTxStatus.Settled;
    }

    if (status == CrossChainMsgStatus.Failed) {
        create_cross_txs[txid].status = CrossChainTxStatus.Failed;
    }

    return true;
}
```

[handler_erc20.cairo#L138-L167](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/handler_erc20.cairo#L138-L167)

```rust
fn receive_cross_chain_callback(ref self: ContractState, cross_chain_msg_id: felt252, from_chain: felt252, to_chain: felt252,
from_handler: u256, to_handler: ContractAddress, cross_chain_msg_status: u8) -> bool{
    assert(to_handler == get_contract_address(),'error to_handler');

    assert(self.settlement_address.read() == get_caller_address(), 'not settlement');

    assert(self.support_handler.read((from_chain, from_handler)) && 
            self.support_handler.read((to_chain, contract_address_to_u256(to_handler))), 'not support handler');

    // AUDIT - missing created_tx check
    assert(self.created_tx.read(cross_chain_msg_id).tx_status == CrossChainTxStatus::PENDING, 'tx status error');

    let erc20 = IERC20MintDispatcher{contract_address: self.token_address.read()};
    if self.mode.read() == SettlementMode::MintBurn{
        erc20.burn_from(get_contract_address(), self.created_tx.read(cross_chain_msg_id).amount);
    }
    let created_tx = self.created_tx.read(cross_chain_msg_id);
    self.created_tx.write(cross_chain_msg_id, CreatedCrossChainTx{
        tx_id: created_tx.tx_id,
        from_chain: created_tx.from_chain,
        to_chain: created_tx.to_chain,
        from:created_tx.from,
        to:created_tx.to,
        from_token: created_tx.from_token,
        to_token: created_tx.to_token,
        amount: created_tx.amount,
        tx_status: CrossChainTxStatus::SETTLED
    });

    return true;
}
```

This missing check will make the problem mentioned in one of our reports [”`send_cross_chain_msg` in Settlement must have `onlyHandler` modifier”] a little different for Cairo, the problem will just not revert when `receive_cross_chain_callback` is called, but will take 0s for each `created_tx` field and will burn 0 from the contract, finalizing the cross-chain transaction and marking the non-existent `txId` as SETTLED, while assuming that the contract acted valid.
 

**Recommendation:**

Add the same check in Cairo's `receive_cross_chain_callback`.

```diff
fn receive_cross_chain_callback(ref self: ContractState, cross_chain_msg_id: felt252, from_chain: felt252, to_chain: felt252,
from_handler: u256, to_handler: ContractAddress, cross_chain_msg_status: u8) -> bool{
    assert(to_handler == get_contract_address(),'error to_handler');

    assert(self.settlement_address.read() == get_caller_address(), 'not settlement');

    assert(self.support_handler.read((from_chain, from_handler)) && 
            self.support_handler.read((to_chain, contract_address_to_u256(to_handler))), 'not support handler');

+   assert(self.created_tx.read(cross_chain_msg_id).tx_status == CrossChainTxStatus::PENDING, 'tx status error');

    let erc20 = IERC20MintDispatcher{contract_address: self.token_address.read()};
    if self.mode.read() == SettlementMode::MintBurn{
        erc20.burn_from(get_contract_address(), self.created_tx.read(cross_chain_msg_id).amount);
    }
    let created_tx = self.created_tx.read(cross_chain_msg_id);
    self.created_tx.write(cross_chain_msg_id, CreatedCrossChainTx{
        tx_id: created_tx.tx_id,
        from_chain: created_tx.from_chain,
        to_chain: created_tx.to_chain,
        from:created_tx.from,
        to:created_tx.to,
        from_token: created_tx.from_token,
        to_token: created_tx.to_token,
        amount: created_tx.amount,
        tx_status: CrossChainTxStatus::SETTLED
    });

    return true;
}
```

## [QA-07] `ERC20TransferPayload` encoding/decoding can be simplified

**Issue Description:**

`deocde_transfer` can be simplified because in `ERC20CodecV1` because none of the params of the `ERC20TransferPayload` struct are of dynamic type (string or bytes). Encoding/decoding can be easily simplified because it doesn’t whether the encoding is packed or not, the output bytes will be always the same, due to the types of properties:

[ERC20CodecV1.sol](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/ERC20CodecV1.sol#L36C5-L46C11)

```solidity
function encode_transfer(
      ERC20TransferPayload memory _payload
  ) external pure returns (bytes memory encodedPaylaod) {
      encodedPaylaod = abi.encodePacked(
          _payload.method_id,
          _payload.from,
          _payload.to,
          _payload.from_token,
          _payload.to_token,
          _payload.amount
      );
  }
```

Additionally the decoding is also heavily complicated it can simply decode to the `ERC20TransferPayload` directly instead of manually parsing and slicing the array:

[ERC20CodecV1.sol](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/ERC20CodecV1.sol#L65C5-L74C6)

```solidity
function deocde_transfer(
        bytes calldata _payload
    ) external pure returns (ERC20TransferPayload memory transferPayload) {
        transferPayload.method_id = ERC20Method(uint8(_payload[0]));
        transferPayload.from = abi.decode(_payload[1:33], (uint256));
        transferPayload.to = abi.decode(_payload[33:65], (uint256));
        transferPayload.from_token = abi.decode(_payload[65:97], (uint256));
        transferPayload.to_token = abi.decode(_payload[97:129], (uint256));
        transferPayload.amount = abi.decode(_payload[129:161], (uint256));
    }
```

**Recommendation:**

`encode_transfer` should be modified like this:

```diff
function encode_transfer(
      ERC20TransferPayload memory _payload
  ) external pure returns (bytes memory encodedPaylaod) {
-     encodedPaylaod = abi.encodePacked(
+     encodedPaylaod = abi.encode(
          _payload.method_id,
          _payload.from,
          _payload.to,
          _payload.from_token,
          _payload.to_token,
          _payload.amount
      );
  }
```

`deocde_transfer` should look like this:

```solidity
function deocde_transfer(
        bytes calldata _payload
    ) external pure returns (ERC20TransferPayload memory transferPayload) {
	     return abi.decode(_payload, (ERC20TransferPayload));
}
```

## [QA-08] superfluous checks in `receive_cross_chain_msg`

**Issue Description:**

`ChakraSettlementHandler::receive_cross_chain_msg` contains 2 identical checks regarding the payload type and one of them is redundant:

[ChakraSettlementHandler.sol](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/ChakraSettlementHandler.sol#L316-L318)

```solidity
function receive_cross_chain_msg(
uint256 /**txid */,
string memory from_chain,
uint256 /**from_address */,
uint256 from_handler,
PayloadType payload_type,
bytes calldata payload,
uint8 /**sign type */,
bytes calldata /**signaturs */
) external onlySettlement returns (bool) {
//  from_handler need in whitelist
if (is_valid_handler(from_chain, from_handler) == false) {
    return false;
}
bytes calldata msg_payload = MessageV1Codec.payload(payload);

require(isValidPayloadType(payload_type), "Invalid payload type");

if (payload_type == PayloadType.ERC20) {
    // Cross chain transfer
    {
    // Decode transfer payload
            ERC20TransferPayload memory transfer_payload = codec
                .deocde_transfer(msg_payload);

            if (mode == SettlementMode.MintBurn) {
                _erc20_mint(
                    AddressCast.to_address(transfer_payload.to),
                    transfer_payload.amount
                );
                return true;
            } else if (mode == SettlementMode.LockUnlock) {
                _erc20_unlock(
                    AddressCast.to_address(transfer_payload.to),
                    transfer_payload.amount
                );

                return true;
            } else if (mode == SettlementMode.LockMint) {
                _erc20_mint(
                    AddressCast.to_address(transfer_payload.to),
                    transfer_payload.amount
                );
                return true;
            } else if (mode == SettlementMode.BurnUnlock) {
                _erc20_unlock(
                    AddressCast.to_address(transfer_payload.to),
                    transfer_payload.amount
                );
                return true;
            }
        }
    }

    return false;
}
```

As we can see the first require `isValidPayloadType` is redundant because the if check below does the same. As a result when the payload type is not `ERC20` we will revert, without even entering the check in the if statement. 

**Recommendation:**

Remove the require statement and add else statement, so when the other payload types are supported it will be easier to upgrade the contracts:

```diff
function receive_cross_chain_msg(
uint256 /**txid */,
string memory from_chain,
uint256 /**from_address */,
uint256 from_handler,
PayloadType payload_type,
bytes calldata payload,
uint8 /**sign type */,
bytes calldata /**signaturs */
) external onlySettlement returns (bool) {
//  from_handler need in whitelist
if (is_valid_handler(from_chain, from_handler) == false) {
    return false;
}
bytes calldata msg_payload = MessageV1Codec.payload(payload);

- require(isValidPayloadType(payload_type), "Invalid payload type");

if (payload_type == PayloadType.ERC20) {
    // Cross chain transfer
    {
    // Decode transfer payload
            ERC20TransferPayload memory transfer_payload = codec
                .deocde_transfer(msg_payload);

            if (mode == SettlementMode.MintBurn) {
                _erc20_mint(
                    AddressCast.to_address(transfer_payload.to),
                    transfer_payload.amount
                );
                return true;
            } else if (mode == SettlementMode.LockUnlock) {
                _erc20_unlock(
                    AddressCast.to_address(transfer_payload.to),
                    transfer_payload.amount
                );

                return true;
            } else if (mode == SettlementMode.LockMint) {
                _erc20_mint(
                    AddressCast.to_address(transfer_payload.to),
                    transfer_payload.amount
                );
                return true;
            } else if (mode == SettlementMode.BurnUnlock) {
                _erc20_unlock(
                    AddressCast.to_address(transfer_payload.to),
                    transfer_payload.amount
                );
                return true;
            }
        }
    }
+ else {
+	   revert("Currently unsupported");
+ }

    return false;
}
```

## [QA-09] `receive_cross_chain_msg` has unnecessary if clause

**Issue Description:**

There is an redundant status assignment in the `ChakraSettlement::receive_cross_chain_msg`:

[ChakraSettlement.sol](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L227-L233)

```solidity
function receive_cross_chain_msg(
    uint256 txid,
    string memory from_chain,
    uint256 from_address,
    uint256 from_handler,
    address to_handler,
    PayloadType payload_type,
    bytes calldata payload,
    uint8 sign_type, // validators signature type /  multisig or bls sr25519
    bytes calldata signatures // signature array
) external {
    ...MORE CODE

    bool result = ISettlementHandler(to_handler).receive_cross_chain_msg(
        txid,
        from_chain,
        from_address,
        from_handler,
        payload_type,
        payload,
        sign_type,
        signatures
    );

    CrossChainMsgStatus status = CrossChainMsgStatus.Failed;
    if (result == true) {
        status = CrossChainMsgStatus.Success;
        receive_cross_txs[txid].status = CrossChainMsgStatus.Success;
    } else {
        receive_cross_txs[txid].status = CrossChainMsgStatus.Failed;
    }

    emit CrossChainHandleResult(
        txid,
        status,
        contract_chain_name,
        from_chain,
        address(to_handler),
        from_handler,
        payload_type
    );
}
```

When `ISettlementHandler(to_handler).receive_cross_chain_msg` is called we need the returned value in order to determine the status of the transaction and emit the event which will trigger the callback, but the `result` variable contains redundant `else` statement:

```solidity
else {
        receive_cross_txs[txid].status = CrossChainMsgStatus.Failed;
    }
```

We can simply assign the default `status` to `Failed` and only have `if`  statement which will change the status to `Success`.

Same if check is observed in `settlement` contract:

[settlement.cairo](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L356-L361)

```rust
fn receive_cross_chain_msg(
            ref self: ContractState,
            cross_chain_msg_id: u256,
            from_chain: felt252,
            to_chain: felt252,
            from_handler: u256,
            to_handler: ContractAddress,
            sign_type: u8,
            signatures: Array<(felt252, felt252, bool)>,
            payload: Array<u8>,
            payload_type: u8,
        ) -> bool {

					...MORE CODE
            // call handler receive_cross_chain_msg
            let handler = IHandlerDispatcher{contract_address: to_handler};
            let success = handler.receive_cross_chain_msg(cross_chain_msg_id, from_chain, to_chain, from_handler, to_handler , payload);

            let mut status = CrossChainMsgStatus::SUCCESS;
            if success{
                status = CrossChainMsgStatus::SUCCESS;
            }else{
                status = CrossChainMsgStatus::FAILED;
            }
```

Here we also want to check what is the status of the execution of `handler_erc20` and emit even with the right status. Now the if is redundant because it won’t change the status.

**Recommendation:**

Remove the else statement and leave only the if check:

```diff
    CrossChainMsgStatus status = CrossChainMsgStatus.Failed;
    if (result == true) {
        status = CrossChainMsgStatus.Success;
-       receive_cross_txs[txid].status = CrossChainMsgStatus.Success;
    } 
-   else {
-       receive_cross_txs[txid].status = CrossChainMsgStatus.Failed;
-   }

+   receive_cross_txs[txid].status = status;
```

And in `Cairo`:

```diff

            // call handler receive_cross_chain_msg
            let handler = IHandlerDispatcher{contract_address: to_handler};
            let success = handler.receive_cross_chain_msg(cross_chain_msg_id, from_chain, to_chain, from_handler, to_handler , payload);

-           let mut status = CrossChainMsgStatus::SUCCESS;
-           if success{
-               status = CrossChainMsgStatus::SUCCESS;
-           }else{
-               status = CrossChainMsgStatus::FAILED;
-           }

+           let mut status = CrossChainMsgStatus::FAILED;
+           if success{
+               status = CrossChainMsgStatus::SUCCESS;
+           }
```

## [QA-10] `verifyECDSA` can have strict equality

**Issue Description:**

Function which is used to check the validator signatures uses **greater than or equal to (≥)** when comparing to the validator threshold number. Indeed such check is not needed because for loop is terminated as long as the `m` == `required_validators` :

[SettlementSignatureVerifier.sol](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/SettlementSignatureVerifier.sol#L207)

```solidity
function verifyECDSA(
      bytes32 msgHash,
      bytes calldata signatures
  ) internal view returns (bool) {
      require(
          signatures.length % 65 == 0,
          "Signature length must be a multiple of 65"
      );

      uint256 len = signatures.length;
      uint256 m = 0;
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

The set of signatures are considered valid when there are valid signatures, equal to the threshold we don’t need to continue check the others.

**Recommendation:**

Replace the ≥ sign with simply ==:

```diff
function verifyECDSA(
      bytes32 msgHash,
      bytes calldata signatures
  ) internal view returns (bool) {
      require(
          signatures.length % 65 == 0,
          "Signature length must be a multiple of 65"
      );

      uint256 len = signatures.length;
      uint256 m = 0;
      for (uint256 i = 0; i < len; i += 65) {
          bytes memory sig = signatures[i:i + 65];
          if (
-             validators[msgHash.recover(sig)] && ++m >= required_validators
+             validators[msgHash.recover(sig)] && ++m == required_validators
          ) {
              return true;
          }
      }

      return false;
  }
```

## [QA-11] `cross_chain_erc20_settlement` is missing address 0 check in Cairo

**Issue Description:**

`cross_chain_erc20_settlement` in `Cairo` is missing check for the `to`,`to_token` addresses provided and users can lose their funds by passing 0 as an argument:

[handler_erc20.cairo](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/handler_erc20.cairo#L167-L181)

```rust
  fn cross_chain_erc20_settlement(ref self: ContractState, to_chain: felt252, to_handler: u256, to_token: u256, to: u256, amount: u256) -> felt252{
      assert(self.support_handler.read((to_chain, to_handler)), 'not support handler');
      let settlement = IChakraSettlementDispatcher {contract_address: self.settlement_address.read()};
      let from_chain = settlement.chain_name();
      let token = IERC20Dispatcher{contract_address: self.token_address.read()};
      let token_burnable = IERC20MintDispatcher{contract_address: self.token_address.read()};
      ...MORE CODE
}
```

This will lead to tokens that are locked/burned on Starknet to be unlocked to `address(0)` on the destination chain meaning that tokens are lost, without a way to be refunded or the function to revert because of 0 passed as to_token.

The function should check this like in Solidity:

[ChakraSettlementHandler.sol#L111-L121](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L111-L121)

```solidity
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

**Recommendation:**

Add check, preventing users from passing 0 as an argument as a destination recipient:

```diff
fn cross_chain_erc20_settlement(ref self: ContractState, to_chain: felt252, to_handler: u256, to_token: u256, to: u256, amount: u256) -> felt252{
      assert(self.support_handler.read((to_chain, to_handler)), 'not support handler');
+     assert(to != 0, '0 address is not possible');
+     assert(to_token != 0, '0 address is not possible');     
      let settlement = IChakraSettlementDispatcher {contract_address: self.settlement_address.read()};
      let from_chain = settlement.chain_name();
      let token = IERC20Dispatcher{contract_address: self.token_address.read()};
      let token_burnable = IERC20MintDispatcher{contract_address: self.token_address.read()};
}
```

## [QA-12] `cross_chain_erc20_settlement` is missing zero amount check

**Issue Description:**

`cross_chain_erc20_settlement` in `Cairo` is missing check for 0 amount tokens and nothing prevents users from creating cross-chain transactions without transferring any tokens. Although no harm can be done this missing check violates one of the invariants defined:

> Cross-chain ERC20 settlements can only be initiated with a valid amount (greater than 0), a valid recipient address, a valid handler address, and a valid token address
> 

[handler_erc20.cairo](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/handler_erc20.cairo#L167-L181)

```rust
  fn cross_chain_erc20_settlement(ref self: ContractState, to_chain: felt252, to_handler: u256, to_token: u256, to: u256, amount: u256) -> felt252{
      assert(self.support_handler.read((to_chain, to_handler)), 'not support handler');
      let settlement = IChakraSettlementDispatcher {contract_address: self.settlement_address.read()};
      let from_chain = settlement.chain_name();
      let token = IERC20Dispatcher{contract_address: self.token_address.read()};
      let token_burnable = IERC20MintDispatcher{contract_address: self.token_address.read()};
      ...MORE CODE
}
```

As we can see there is no such check.

**Recommendation:**

Add check, preventing users from creating cross-chain msgs when amount passed is 0:

```diff
fn cross_chain_erc20_settlement(ref self: ContractState, to_chain: felt252, to_handler: u256, to_token: u256, to: u256, amount: u256) -> felt252{
      assert(self.support_handler.read((to_chain, to_handler)), 'not support handler');
+     assert(amount > 0, '0 amount is not possible');     
      let settlement = IChakraSettlementDispatcher {contract_address: self.settlement_address.read()};
      let from_chain = settlement.chain_name();
      let token = IERC20Dispatcher{contract_address: self.token_address.read()};
      let token_burnable = IERC20MintDispatcher{contract_address: self.token_address.read()};
}
```

## [QA-13] `set_required_validators_num` should have check if `req_validator` < `validator_count`

**Issue Description:**

`set_required_validators_num` should check whether the `_required_validators` argument isn’t higher than the current `validator_count`. Otherwise contracts can end up in state where even if all the validators are active and provide signatures, they also won’t be enough to validate cross-chain transaction. Currently such check is not presented and manager can intentionally, or not pass higher number than the number of current validators and DoS the cross-chain functionality until another manager doesn’t decrease the value:

[BaseSettlement.sol](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/BaseSettlement.sol#L121-L127)

```solidity
function set_required_validators_num(
        uint256 _required_validators
    ) external virtual onlyRole(MANAGER_ROLE) {
        uint256 old = required_validators;
        required_validators = _required_validators;
        emit RequiredValidatorsChanged(msg.sender, old, required_validators);
    }
```

**Recommendation:**

Add a check to prevent even the managers from passing `_required_validators` higher than the number of the validators:

```diff
function set_required_validators_num(
        uint256 _required_validators
    ) external virtual onlyRole(MANAGER_ROLE) {
+       require(_required_validators <= validator_count, "req exceeds current number of validators");
        uint256 old = required_validators;
        required_validators = _required_validators;
        emit RequiredValidatorsChanged(msg.sender, old, required_validators);
    }
```

## [QA-14] missing `disableInitializers` in `SettlementSignatureVerifier`

**Issue Description:**

`SettlementSignatureVerifier` is missing `disableInitializers` call and due to the usage of a proxy upgradeable contract without calling this function in the constructor of the logic contract. This oversight introduces a severe risk, allowing potential attackers to initialize the implementation contract itself.

**Recommendation:**

Call `disableInitializers`: Include a call to `disableInitializers` in the constructor of the logic contract as recommended by OpenZeppelin.

[SettlementSignatureVerifier.sol](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/SettlementSignatureVerifier.sol#L16)

```diff
+	constructor() external {
+		disableInitializers()
+	}
```

## [QA-15] `txId` is generated differently on Starknet

**Issue Description:**

`tx_id` in `handler_erc20` is generated differently, compared to `ChakraSettlementHandler`.

In Cairo it contains the following params:

- `transaction_hash`
- `msg_count`

[ChakraSettlementHandler.sol](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/ChakraSettlementHandler.sol#L139C9-L150C11)

```solidity
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

    if (mode == SettlementMode.MintBurn) {
        _erc20_lock(msg.sender, address(this), amount);
    } else if (mode == SettlementMode.LockUnlock) {
        _erc20_lock(msg.sender, address(this), amount);
    } else if (mode == SettlementMode.LockMint) {
        _erc20_lock(msg.sender, address(this), amount);
    } else if (mode == SettlementMode.BurnUnlock) {
        _erc20_burn(msg.sender, amount);
    }

    {
        // Increment nonce for the sender
        nonce_manager[msg.sender] += 1;
    }

    // Create a new cross chain tx
    uint256 txid = uint256(
        keccak256(
            abi.encodePacked(
                chain,
                to_chain,
                msg.sender, // from address for settlement to calculate txid
                address(this), //  from handler for settlement to calculate txid
                to_handler,
                nonce_manager[msg.sender]
            )
        )
  );
```

In Solidity it contains the following params:

- `chain`
- `to_chain`
- `msg.sender`
- `address(this)`
- `to_handler`
- `nonce of caller`

[handler_erc20.cairo](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/handler_erc20.cairo#L167C9-L183C105)

```rust
fn cross_chain_erc20_settlement(ref self: ContractState, to_chain: felt252, to_handler: u256, to_token: u256, to: u256, amount: u256) -> felt252{
			...MORE CODE
      
      let tx_id = LegacyHash::hash(get_tx_info().unbox().transaction_hash, self.msg_count.read());
```

As we can see both `tx_ids` are completely different from each other. But the intentions of the team is to construct hashes in the same way on both chains. Making the management of the transactions across different chains, `Starknet` and `EVM` in particular easier. Now they will have to have different signing logic, depending on the chain that the transaction comes.

Furthermore, the approach used in `Cairo` can potentially lead to duplicate `tx_ids`, because only 2 values are being used, both of simple types. If such scenario happens the second user will break the invariant defined in the project’s because of the active checks, preventing replays in the `receive_cross_chain_callback` functions:

> The contract maintains a consistent state between locking/burning tokens on the source chain and minting/unlocking on the destination chain, depending on the settlement mode.
> 

**Recommendation:**

Modify the `handler_erc20` contract to compute the `tx_id` in the same way as in `ChakraSettlementHandler`:

```diff
fn cross_chain_erc20_settlement(ref self: ContractState, to_chain: felt252, to_handler: u256, to_token: u256, to: u256, amount: u256) -> felt252{
			...MORE CODE
      
-      let tx_id = LegacyHash::hash(get_tx_info().unbox().transaction_hash, self.msg_count.read());
+      let tx_id = LegacyHash::hash(self.chain_name.read(), (to_chain, get_caller_address(), get_contract_address(), to_handler, self.msg_count.read());
```

## [QA-16] Message.id wrongly downcasted to uint64

**Issue Description:**

in `MessageV1Codec` library `id` is wrongly decoded to `uint64`, instead of the original size when being encoded - `uint256`. The `_msg` that this function expects is the `Message` struct that looks like this:

[Message.sol](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/libraries/Message.sol#L32-L39)

```solidity
struct Message {
    // The id of the message
    uint256 id;
    // The type of the payload
    PayloadType payload_type;
    // The payload of the message
    bytes payload;
}
```

as we can see the id is of type `uint256` but in `MessageV1Codec::id` it’s downcasted and will return only the rightmost bits:

[MessageV1Codec.sol](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/libraries/MessageV1Codec.sol#L57)

```solidity
function id(bytes calldata _msg) internal pure returns (uint64) {
      return uint64(bytes8(_msg[ID_OFFSET:PAYLOAD_TYPE_OFFSET]));
  }
```

**Recommendation:**

Apply the following changes to this function in order to return the original id that the `Message` struct is encoded with:

```diff
- function id(bytes calldata _msg) internal pure returns (uint64) {
+ function id(bytes calldata _msg) internal pure returns (uint256) {
-     return uint64(bytes8(_msg[ID_OFFSET:PAYLOAD_TYPE_OFFSET]));
+     return uint256(bytes32(_msg[ID_OFFSET:PAYLOAD_TYPE_OFFSET]));
   }
```

## [QA-17] Whole system is missing pausability

**Issue Description:**

All the contracts in scope are missing pausability mechanism and in case of a failure will not be able to be stopped. This poses significant risk especially in cross-chain protocols where `handlers` (`ChakraSettlementHandler` and `handler_erc20`) are in complete control over the locked funds of the users or can be used to mint the entire supply of the Chakra token in this scenario.

By having `pause/unpause` functions and `whenNotPaused` modifiers applied you will minimize the risk in case there is an issue in your contracts. When paused you can think of a plan to rescue the funds. Pausing is also beneficial when upgrade is performed, that way you will eliminate the risk of failing cross-chain transactions when, for example, important variable is being changed. 

Without a way to pause `cross_chain_erc20_settlement` you can’t stop users from spamming transactions when contracts are malfunctioning. 

**Recommendation:**

In order to fix this you should:

1. import the `PausableUpgradeable` contract from `OpenZeppelin`:

https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable/blob/master/contracts/utils/PausableUpgradeable.sol

1. expose `onlyOwner` public `pause/unpause` functions 
2. add the `whenNotPaused` modifier to any of the critical functions, such as `cross_chain_erc20_settlement` and in `ChakraToken's` `mint`, `burn`, `burn_from`, `mint_to`.

## [QA-18] Cross-chain txs always revert in case are invalid, instead of setting status = `FAILED`

**Issue Description:**

There are `else` clauses in Cairo contracts that are unreachable because all calls before them always return the same value, and the `else` will never be entered.

The first case is in `receive_cross_chain_msg`. A call made to `handler.receive_cross_chain_msg` will always return `true`, not allowing the `Status` to be `Failed`, since all cases that result in a cross-chain tx to fail are strictly asserted in the handler, and this else will never be reached.

[settlement.cairo#L387-L396](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/settlement.cairo#L356-L361)

```rust
fn receive_cross_chain_msg(
    ref self: ContractState,
    cross_chain_msg_id: u256,       
    from_chain: felt252,
    to_chain: felt252,
    from_handler: u256,
    to_handler: ContractAddress,
    sign_type: u8,
    signatures: Array<(felt252, felt252, bool)>,
    payload: Array<u8>,
    payload_type: u8,
) -> bool {
    ...
    

    // call handler receive_cross_chain_msg
    let handler = IHandlerDispatcher{contract_address: to_handler};
    let success = handler.receive_cross_chain_msg(cross_chain_msg_id, from_chain, to_chain, from_handler, to_handler , payload);

    let mut status = CrossChainMsgStatus::SUCCESS;
    if success{ 
        status = CrossChainMsgStatus::SUCCESS;
    }else{
        status = CrossChainMsgStatus::FAILED;
    }
```

[handler_erc20.cairo#L108-L136](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/handler_erc20.cairo#L108-L136)

```rust
fn receive_cross_chain_msg(ref self: ContractState, cross_chain_msg_id: u256, from_chain: felt252, to_chain: felt252,
from_handler: u256, to_handler: ContractAddress, payload: Array<u8>) -> bool{
    assert(to_handler == get_contract_address(),'error to_handler');

    assert(self.settlement_address.read() == get_caller_address(), 'not settlement');

    assert(self.support_handler.read((from_chain, from_handler)) && 
            self.support_handler.read((to_chain, contract_address_to_u256(to_handler))), 'not support handler');

    let message :Message= decode_message(payload);
    let payload_type = message.payload_type;
    assert(payload_type == PayloadType::ERC20, 'payload type not erc20');
    let payload_transfer = message.payload;
    let transfer = decode_transfer(payload_transfer);
    assert(transfer.method_id == ERC20Method::TRANSFER, 'ERC20Method must TRANSFER');
    let erc20 = IERC20MintDispatcher{contract_address: self.token_address.read()};
    let token = IERC20Dispatcher{contract_address: self.token_address.read()};
    if self.mode.read() == SettlementMode::MintBurn{
        erc20.mint_to(u256_to_contract_address(transfer.to), transfer.amount);
    }else if self.mode.read() == SettlementMode::LockMint{
        erc20.mint_to(u256_to_contract_address(transfer.to), transfer.amount);
    }else if self.mode.read() == SettlementMode::BurnUnlock{
        token.transfer(u256_to_contract_address(transfer.to), transfer.amount);
    }else if self.mode.read() == SettlementMode::LockUnlock{
        token.transfer(u256_to_contract_address(transfer.to), transfer.amount);
    }
    
    return true;
}
```

The other case is in `receive_cross_chain_callback`, the call to `handler.receive_cross_chain_callback` again always return `true`.

[settlement.cairo#L415-L421](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/settlement.cairo#L415-L421)

```rust
fn receive_cross_chain_callback(
    ref self: ContractState,
    cross_chain_msg_id: felt252,
    from_chain: felt252,
    to_chain: felt252,
    from_handler: u256,
    to_handler: ContractAddress,
    cross_chain_msg_status: u8,
    sign_type: u8,
    signatures: Array<(felt252, felt252, bool)>,
) -> bool {
    ...
    let handler = IHandlerDispatcher{contract_address: to_handler};
    let success = handler.receive_cross_chain_callback(cross_chain_msg_id, from_chain, to_chain, from_handler, to_handler , cross_chain_msg_status);
    let mut state = CrossChainMsgStatus::PENDING;
    if success{
        state = CrossChainMsgStatus::SUCCESS;
    }else{
        state = CrossChainMsgStatus::FAILED;
    }
```

[handler_erc20.cairo#L138-L165](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/handler_erc20.cairo#L138-L165)

```rust
fn receive_cross_chain_callback(ref self: ContractState, cross_chain_msg_id: felt252, from_chain: felt252, to_chain: felt252,
from_handler: u256, to_handler: ContractAddress, cross_chain_msg_status: u8) -> bool{
    assert(to_handler == get_contract_address(),'error to_handler');

    assert(self.settlement_address.read() == get_caller_address(), 'not settlement');

    assert(self.support_handler.read((from_chain, from_handler)) && 
            self.support_handler.read((to_chain, contract_address_to_u256(to_handler))), 'not support handler');

    let erc20 = IERC20MintDispatcher{contract_address: self.token_address.read()};
    if self.mode.read() == SettlementMode::MintBurn{
        erc20.burn_from(get_contract_address(), self.created_tx.read(cross_chain_msg_id).amount);
    }
    let created_tx = self.created_tx.read(cross_chain_msg_id);
    self.created_tx.write(cross_chain_msg_id, CreatedCrossChainTx{
        tx_id: created_tx.tx_id,
        from_chain: created_tx.from_chain,
        to_chain: created_tx.to_chain,
        from:created_tx.from,
        to:created_tx.to,
        from_token: created_tx.from_token,
        to_token: created_tx.to_token,
        amount: created_tx.amount,
        tx_status: CrossChainTxStatus::SETTLED
    });

    return true;
}
```

**Recommendation:**

Return `false` in all cases where the cross-tx is not valid, and don't use `assert`, causing the transaction to reverted, which is the better implementation, since all cross-tx should finalize their flow, not to revert in the middle and to not be updated everywhere that they are with status = `FAILED`.

## [QA-19] Wrong `message_hash` in `receive_cross_chain_msg` on  Starknet compared to EVM

**Issue Description:**

`message_hash` of `receive_cross_chain_msg`, constructed in `ChakraSettlement.sol` is completely different from the `message_hash` in `settlement.cairo` .

In Solidity it’s constructed from:

- `txid`
- `from_chain`
- `from_address`
- `from_handler`
- `to_handler`
- `hash of payload`

[ChakraSettlement.sol](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L183C12-L192C15)

```solidity
function receive_cross_chain_msg(
    uint256 txid,
    string memory from_chain,
    uint256 from_address,
    uint256 from_handler,
    address to_handler,
    PayloadType payload_type,
    bytes calldata payload,
    uint8 sign_type, // validators signature type /  multisig or bls sr25519
    bytes calldata signatures // signature array
) external {
    {
        // verify signature
        bytes32 message_hash = keccak256(
            abi.encodePacked(
                txid,
                from_chain,
                from_address,
                from_handler,
                to_handler,
                keccak256(payload)
            )
        );
```

In Cairo it’s constructed from:

- `from_chain`
- `cross_chain_msg_id` (txid)
- `to_chain`
- `from_handler`
- `to_handler`
- `hash of payload`

[settlement.cairo](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L325C8-L349C15)

```rust
 fn receive_cross_chain_msg(
            ref self: ContractState,
            cross_chain_msg_id: u256,
            from_chain: felt252,
            to_chain: felt252,
            from_handler: u256,
            to_handler: ContractAddress,
            sign_type: u8,
            signatures: Array<(felt252, felt252, bool)>,
            payload: Array<u8>,
            payload_type: u8,
        ) -> bool {
            assert(to_chain == self.chain_name.read(), 'error to_chain');

            // verify signatures
            let mut message_hash: felt252 = LegacyHash::hash(from_chain, (cross_chain_msg_id, to_chain, from_handler, to_handler));
            let payload_span = payload.span();
            let mut i = 0;
            loop {
                if i > payload_span.len()-1{
                    break;
                }
                message_hash = LegacyHash::hash(message_hash, * payload_span.at(i));
                i += 1;
        };
```

As we can see the order is different and there is `to_chain` instead of `from_address` in `Cairo`. But the intentions of the team is to construct hashes in the same way on both chains. Making the signing of the messages easier and the same for all validators.

**Recommendation:**

Modify the `message_hash` in Cairo by adding `from_address` like the one in Solidity and use the `chain_name` storage variable instead of allowing users to pass it as an argument:

```diff
- let mut message_hash: felt252 = LegacyHash::hash(from_chain, (cross_chain_msg_id, to_chain, from_handler, to_handler));
+ let mut message_hash: felt252 = LegacyHash::hash(cross_chain_msg_id, (from_chain, chain_name, from_handler, to_handler));
        let payload_span = payload.span();
        let mut i = 0;
        loop {
            if i > payload_span.len()-1{
                break;
            }
            message_hash = LegacyHash::hash(message_hash, * payload_span.at(i));
            i += 1;
        };
        self.check_chakra_signatures(message_hash, signatures);
```

Or if the Starknet one is better (as we don't know what is the correct intention of the developers), in Solidity you just have to replace the `from_address` with `contract_chain_name`:

```diff
 bytes32 message_hash = keccak256(
                abi.encodePacked(
                    txid,
                    from_chain,
-                   from_address,
+                   contract_chain_name,
                    from_handler,
                    to_handler,
                    keccak256(payload)
                )
            );

```

## [QA-20] Wrong `message_hash` in `receive_cross_chain_callback` on Starknet compared to EVM

**Issue Description:**

`message_hash` of `receive_cross_chain_callback`, constructed in `ChakraSettlement.sol` is completely different from the `message_hash` in `settlement.cairo` .

In Solidity it’s constructed from:

- `txid`
- `from_handler`
- `to_handler`
- `status`

[ChakraSettlement.sol](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L285C5-L301C6)

```solidity
function verifySignature(
      uint256 txid,
      uint256 from_handler,
      address to_handler,
      CrossChainMsgStatus status,
      uint8 sign_type,
      bytes calldata signatures
  ) internal view {
      bytes32 message_hash = keccak256(
          abi.encodePacked(txid, from_handler, to_handler, status)
      );

      require(
          signature_verifier.verify(message_hash, signatures, sign_type),
          "Invalid signature"
      );
  }
```

In Cairo it’s constructed from:

- `from_chain`
- `cross_chain_msg_id` (txid)
- `to_chain`
- `from_handler`
- `to_handler`
- `status`

[settlement.cairo](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L393C9-L413C74)

```rust
fn receive_cross_chain_callback(
          ref self: ContractState,
          cross_chain_msg_id: felt252,
          from_chain: felt252,
          to_chain: felt252,
          from_handler: u256,
          to_handler: ContractAddress,
          cross_chain_msg_status: u8,
          sign_type: u8,
          signatures: Array<(felt252, felt252, bool)>,
      ) -> bool {
          assert(self.created_tx.read(cross_chain_msg_id).tx_id == cross_chain_msg_id, 'message id error');
          assert(self.created_tx.read(cross_chain_msg_id).from_chain == to_chain, 'from_chain error');
          assert(self.created_tx.read(cross_chain_msg_id).to_chain == from_chain, 'to_chain error');
          assert(self.created_tx.read(cross_chain_msg_id).from_handler == to_handler, 'from_handler error');
          assert(self.created_tx.read(cross_chain_msg_id).to_handler == from_handler, 'to_handler error');
          assert(self.created_tx.read(cross_chain_msg_id).tx_status == CrossChainMsgStatus::PENDING, 'tx status error');

          let mut message_hash_temp: felt252 = LegacyHash::hash(from_chain, (cross_chain_msg_id, to_chain, from_handler, to_handler));
          let message_hash_final:felt252 = LegacyHash::hash(message_hash_temp, cross_chain_msg_status);
          self.check_chakra_signatures(message_hash_final, signatures);
```

As we can see the order is different and `from_chain`, `to_chain` are missing in `Solidity`. But the intentions of the team is to construct hashes in the same way on both chains.

**Recommendation:**

Modify the `message_hash` in Solidity to look like that (use the `contract_chain_name` storage variable and do not allow users to pass it as an argument, use the storage variable), or if the Solidity one (without chain names) is the right one, remove the `from_chain`, `to_chain` from the hash on Starknet.

```diff
bytes32 message_hash = keccak256(
-        abi.encodePacked(txid, from_handler, to_handler, status)
+        abi.encodePacked(from_chain, txid, contract_chain_name, from_handler, to_handler, status)
    );
```

## [QA-21] Protocol hashes do not use `EIP712`

**Issue Description:**

Signatures that validators provide in order to validate the messages are not compliant with the `EIP712`, as a result they will be unreadable by wallets as `Metamask` and can pose some difficulties for the signers.

The most crucial discrepancies are the fact that there is no `domainSeparator` (that includes the version, chainId, address of the verifying contract and salt, used to prevent replays), `hashStruct`(the hashed struct  , in Chakra’s case - `message_hash`, it has to have defined struct and it’s signature should be hashed) and `encodeData` (that included the message that should be signed, in Chakra’s case the `message_hash` itself which contains all the params that make sense for the logical execution).

That will make the whole message signing more easier and readable. Currently we are expecting sign `bytes` array that is manually processed from the validators:

[ChakraSettlement.sol](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L285C5-L301C6)

```solidity
function verifySignature(
        uint256 txid,
        uint256 from_handler,
        address to_handler,
        CrossChainMsgStatus status,
        uint8 sign_type,
        bytes calldata signatures
    ) internal view {
        bytes32 message_hash = keccak256(
            abi.encodePacked(txid, from_handler, to_handler, status)
        );

        require(
            signature_verifier.verify(message_hash, signatures, sign_type),
            "Invalid signature"
        );
    }
```

**Recommendation:**

Add the [EIP712](https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct) support, in order to make the process of signing easier and displaying signatures in a more readable format as well. 

- New message data struct that contains all the important params (the ones that are used from the `message_hash` currently)