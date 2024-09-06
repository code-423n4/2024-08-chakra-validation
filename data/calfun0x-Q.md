## Title
Any manager could leave the protocol without managers in ckr_btc.cairo

## Description
`remove_manager` function in `ckr_btc.cairo` lack of control to remove himself letting a manager remove all managers and himself.
[![GitHub code snippet](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/ckr_btc.cairo#L148C1-L161C10)](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/ckr_btc.cairo#L148C1-L161C10)
```rust
fn remove_manager(ref self: ContractState, old_manager: ContractAddress) -> bool {
    let caller = get_caller_address();
    assert(self.chakra_managers.read(caller) == 1, Errors::NOT_MANAGER);
    self.chakra_managers.write(old_manager, 0);
    // ...
}
```

## Impact
This could lead to remove all managers from the protocol (included himself) and nobody else could add or remove operators in the future.

## Proof of Concept

Add this POC to cairo/handler/src/tests/test_settlement.cairo
```rust
#[test]
fn test_remove_all_managers(){
    let owner_address = 0x5a9bd6214db5b229bd17a4050585b21c87fc0cadf9871f89a099d27ef800a40;
    let manager1_address = starknet::contract_address_const::<'manager1_address'>();
    let manager2_address = starknet::contract_address_const::<'manager2_address'>();
    
    let ckrBTC_contract = declare("ckrBTC");
    // Add owner as manager in constructor
    let ckrBTC_address = ckrBTC_contract.deploy(@array![owner_address]).unwrap();
    let ckrbtc_dispath = IckrBTCDispatcher{contract_address: ckrBTC_address};
    
    let owner = owner_address.try_into().unwrap();

    // Add manager1 and manager2
    start_prank(CheatTarget::One(ckrBTC_address), owner);
    ckrbtc_dispath.add_manager(manager1_address);
    ckrbtc_dispath.add_manager(manager2_address);
    stop_prank(CheatTarget::One(ckrBTC_address));

    // Manager2 remove all managers (included himself and owner)
    start_prank(CheatTarget::One(ckrBTC_address), manager2_address);
    ckrbtc_dispath.remove_manager(owner);
    ckrbtc_dispath.remove_manager(manager1_address);
    ckrbtc_dispath.remove_manager(manager2_address);
    stop_prank(CheatTarget::One(ckrBTC_address));

    assert(ckrbtc_dispath.is_manager(owner) == false, 'owner is still manager');
    assert(ckrbtc_dispath.is_manager(manager1_address) == false, 'manager1 is still manager');
    assert(ckrbtc_dispath.is_manager(manager2_address) == false, 'manager2 is still manager');
}
```

## Tools Used
Manual revision

## Recommended Mitigation Steps
Add a control to prevent auto-remove or (as in solidity) allow the owner to add new managers.
```rust
fn remove_manager(ref self: ContractState, old_manager: ContractAddress) -> bool {
    // ...
    assert(old_manager != caller, 'cant remove yourself');
    // ...
}
```

## Title
Any manager could leave the protocol without managers in cairo/handler/src/settlement.cairo

## Description
`remove_manager` function in `cairo/handler/src/settlement.cairo` lack of control to remove himself letting a manager remove all managers and himself.
[![GitHub code snippet](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L260C1-L273C10)](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L260C1-L273C10)
```rust
fn remove_manager(ref self: ContractState, old_manager: ContractAddress) -> bool {
    let caller = get_caller_address();
    assert(self.chakra_managers.read(caller) == 1, 'Caller is not a manager');
    self.chakra_managers.write(old_manager, 0);
    // ...
}
```

## Impact
This could lead to remove all managers from the protocol (included himself) and nobody else could add or remove validator or set required num validators in the future.

## Proof of Concept

Add this POC to cairo/handler/src/tests/test_settlement.cairo
```rust
use settlement_cairo::interfaces::IChakraSettlement;

#[test]
fn test_remove_all_settlement_managers(){
    let owner_address = 0x5a9bd6214db5b229bd17a4050585b21c87fc0cadf9871f89a099d27ef800a40;
    let manager1_address = starknet::contract_address_const::<'manager1_address'>();
    let manager2_address = starknet::contract_address_const::<'manager2_address'>();
    
    // Add owner as manager in constructor
    let settlement_contract = declare("ChakraSettlement");
    let settlement_address = settlement_contract.deploy(@array![owner_address, 1]).unwrap();
    let settlement_dispath = IChakraSettlementDispatcher{contract_address: settlement_address};
    
    let owner = owner_address.try_into().unwrap();

    // Add manager1 and manager2
    start_prank(CheatTarget::One(settlement_address), owner);
    settlement_dispath.add_manager(manager1_address);
    settlement_dispath.add_manager(manager2_address);
    stop_prank(CheatTarget::One(settlement_address));

    // Manager2 remove all managers (included himself and owner)
    start_prank(CheatTarget::One(settlement_address), manager2_address);
    settlement_dispath.remove_manager(owner);
    settlement_dispath.remove_manager(manager1_address);
    settlement_dispath.remove_manager(manager2_address);
    stop_prank(CheatTarget::One(settlement_address));

    assert(settlement_dispath.is_manager(owner) == false, 'owner is still manager');
    assert(settlement_dispath.is_manager(manager1_address) == false, 'manager1 is still manager');
    assert(settlement_dispath.is_manager(manager2_address) == false, 'manager2 is still manager');
}
```

## Tools Used
Manual revision

## Recommended Mitigation Steps
Add a control to prevent auto-remove or (as in solidity) allow the owner to add new managers.
```rust
fn remove_manager(ref self: ContractState, old_manager: ContractAddress) -> bool {
    // ...
    assert(old_manager != caller, 'cant remove yourself');
    // ...
}
```

## Title
Missed event for admin operation in cairo functions

## Description
The functions `set_required_validators_num` in `cairo/handler/src/settlement.cairo` lacks of events for administrative writing operations which is a best practice for admin operations.
[![GitHub code snippet](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L197C1-L202C10)](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L197C1-L202C10)
```rust
fn set_required_validators_num(ref self: ContractState, new_num: u32) -> u32 {
    let caller = get_caller_address();
    assert(self.chakra_managers.read(caller) == 1, 'Caller is not a manager');
    self.required_validators_num.write(new_num);
    return self.required_validators_num.read();
}
```

## Impact
Lost of critical records to audit administrator activities and keep transparency for third parties.

## Proof of Concept
N/A

## Tools Used
Manual revision

## Recommended Mitigation Steps
Emit an event after change adminitrative variables status.

## Title
Missed checks in Cairo functions that exists on Solidity functions with the same logic.

## Description
The next functions in cairo files miss the existing checks in Solidity files:

```rust
fn cross_chain_erc20_settlement( ... ) -> felt252{
    // ...
};
```

```solidity
function cross_chain_erc20_settlement( ... ) external {
    require(amount > 0, "Amount must be greater than 0");
    require(to != 0, "Invalid to address");
    require(to_handler != 0, "Invalid to handler address");
    require(to_token != 0, "Invalid to token address");
```

```rust
fn receive_cross_chain_callback( ... ) -> bool{
    // ...
}
```

```solidity
function receive_cross_chain_callback( ... ) external onlySettlement returns (bool) {
    // ...
    require(
        create_cross_txs[txid].status == CrossChainTxStatus.Pending,
        "invalid CrossChainTxStatus"
    );
    // ...
}
```

```rust
fn receive_cross_chain_msg( ... ) -> bool {
    // ...
}
```

```solidity
function receive_cross_chain_msg( ... ) external {
    require(
        receive_cross_txs[txid].status == CrossChainMsgStatus.Unknow,
        "Invalid transaction status"
    );
}
```

## Impact
Inconsistency between same logic in different programming languages ​​makes it difficult for programmers to find bugs and implement future maintenance.

## Proof of Concept
N/A

## Tools Used
Manual revision

## Recommended Mitigation Steps
Add missing Solidity checks into Cairo functions.

## Title
Missed checks in Solidity functions that exists on Cairo functions with the same logic.

## Description
The next functions in solidity files miss the existing checks in Cairo files:

```solidity
function processCrossChainCallback( ... ) internal {
    // ...
}
```

```rust
fn receive_cross_chain_callback( ... ) -> bool {
    assert(self.created_tx.read(cross_chain_msg_id).tx_id == cross_chain_msg_id, 'message id error');
    assert(self.created_tx.read(cross_chain_msg_id).from_chain == to_chain, 'from_chain error');
    assert(self.created_tx.read(cross_chain_msg_id).to_chain == from_chain, 'to_chain error');
    assert(self.created_tx.read(cross_chain_msg_id).from_handler == to_handler, 'from_handler error');
    assert(self.created_tx.read(cross_chain_msg_id).to_handler == from_handler, 'to_handler error');
    // ...
}
```


```solidity
fn receive_cross_chain_msg( ... ) -> bool {
    // ...
}
```

```rust
fn receive_cross_chain_msg( ... ) -> bool {
    // ...
    assert(to_chain == self.chain_name.read(), 'error to_chain');
    // ...
}
```

## Impact
Inconsistency between same logic in different programming languages ​​makes it difficult for programmers to find bugs and implement future maintenance.

## Proof of Concept
N/A

## Tools Used
Manual revision

## Recommended Mitigation Steps
Add missing Cairo checks into Solidity functions.

## Title
Wrong data values written in Cairo event.

## Description
The next events write wrong information into events:

file: settlement.cairo
function receive_cross_chain_msg
```cairo
self.emit(CrossChainHandleResult{
    cross_chain_settlement_id: cross_chain_msg_id,
    from_chain: to_chain,        <- Wrong from_chain!=to_chain
    from_handler: to_handler,    <- Wrong
    to_chain: from_chain,        <- Wrong
    to_handler: from_handler,    <- Wrong
    cross_chain_msg_status: status,
    payload_type: payload_type
});
```

## Impact
Offchain platforms reading wrong information from blockchain network.

## Proof of Concept
N/A

## Tools Used
Manual revision

## Recommended Mitigation Steps
Fix variables used that do not correspond with the event fields.

## Title
Wrong data values written in Solidity event.

## Description
The next events write wrong information into events:

```solidity
emit CrossChainHandleResult(
    txid,
    status,
    contract_chain_name, <- This should be from_chain
    from_chain,          <- This should be to_chain
    address(to_handler), <- This should be from_handler
    from_handler,        <- This should be to_handler
    payload_type
);

event CrossChainHandleResult(
    uint256 indexed txid,
    CrossChainMsgStatus status,
    string from_chain,
    string to_chain,
    address from_handler,
    uint256 to_handler,
    PayloadType payload_type
);
```

## Impact
Offchain platforms reading wrong information from blockchain network.

## Proof of Concept
N/A

## Tools Used
Manual revision

## Recommended Mitigation Steps
Fix variables used that do not correspond with the event fields.