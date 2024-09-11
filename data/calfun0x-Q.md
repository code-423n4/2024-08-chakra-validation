## Title (1/6)
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



## Title (2/6)
Missed checks in Cairo functions that exists on Solidity functions with the same logic.

## Description
The next functions in cairo files miss the existing checks in same logic from Solidity files:

1. Missed checks for zero values in Cairo.
File:cairo/handler/src/handler_erc20.cairo
[![GitHub code snippet](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/handler_erc20.cairo#L167C1-L181C14)](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/handler_erc20.cairo#L167C1-L181C14)
```rust
fn cross_chain_erc20_settlement( ... ) -> felt252{
    // ...
};
```

File:solidity/handler/contracts/ChakraSettlementHandler.sol
[![GitHub code snippet](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/ChakraSettlementHandler.sol#L111C1-L121C60)](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/ChakraSettlementHandler.sol#L111C1-L121C60)
```solidity
function cross_chain_erc20_settlement( ... ) external {
    require(amount > 0, "Amount must be greater than 0");
    require(to != 0, "Invalid to address");
    require(to_handler != 0, "Invalid to handler address");
    require(to_token != 0, "Invalid to token address");
```

2. Missed checks for status in Cairo receive callback.
File:cairo/handler/src/settlement.cairo
[![GitHub code snippet](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L393C9-L442C10)](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L393C9-L442C10)
```rust
fn receive_cross_chain_callback( ... ) -> bool{
    // ...
}
```

File:solidity/settlement/contracts/ChakraSettlement.sol
[![GitHub code snippet](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L312C1-L315C11)](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L312C1-L315C11)
```solidity
function processCrossChainCallback( ... ) internal {
    // ...
    require(
        create_cross_txs[txid].status == CrossChainTxStatus.Pending,
        "Invalid transaction status"
    );
    // ...
}
```

3. Missed checks for status in Cairo receive msg.
File:cairo/handler/src/handler_erc20.cairo
[![GitHub code snippet](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/handler_erc20.cairo#L108C9-L136C10)](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/handler_erc20.cairo#L108C9-L136C10)
```rust
fn receive_cross_chain_msg( ... ) -> bool {
    // ...
}
```

File:solidity/settlement/contracts/ChakraSettlement.sol
[![GitHub code snippet](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L199C1-L202C15)](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L199C1-L202C15)
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



## Title (3/6)
Missed checks in Solidity functions that exists on Cairo functions with the same logic.

## Description
The next functions in solidity files miss the existing checks in Cairo files:

1. Missed checks for right values in Solidity receive callback.
File:solidity/settlement/contracts/ChakraSettlement.sol
[![GitHub code snippet](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L303C5-L331C6)](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L303C5-L331C6)
```solidity
function processCrossChainCallback( ... ) internal {
    // ...
}
```

File:cairo/handler/src/settlement.cairo
[![GitHub code snippet](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L404C1-L409C123)](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L404C1-L409C123)
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

2. Missed checks for `to chain` in Solidity receive callback.
File:solidity/settlement/contracts/ChakraSettlement.sol
[![GitHub code snippet](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L170C5-L244C6)](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L170C5-L244C6)
```solidity
fn receive_cross_chain_msg( ... ) -> bool {
    // ...
}
```

File:cairo/handler/src/settlement.cairo
[![GitHub code snippet](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L337C5-L337C74)](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L337C5-L337C74)
```rust
fn receive_cross_chain_msg( ... ) -> bool {
    // ...
    assert(to_chain == self.chain_name.read(), 'error to_chain');
    // ...
}
```

3. Missed checks for `to handler` in Solidity receive msg.
File:https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/ChakraSettlementHandler.sol#L300C5-L355C6
[![GitHub code snippet](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/ChakraSettlementHandler.sol#L300C5-L355C6)](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/ChakraSettlementHandler.sol#L300C5-L355C6)
```solidity
fn receive_cross_chain_msg( ... ) -> bool {
    // ...
}
```

File:cairo/handler/src/handler_erc20.cairo
[![GitHub code snippet](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/handler_erc20.cairo#L110C1-L111C1)](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/handler_erc20.cairo#L110C1-L111C1)
```rust
fn receive_cross_chain_msg( ... ) -> bool{
    assert(to_handler == get_contract_address(),'error to_handler');
    // ...
}
```

## Impact
Inconsistency between same logic in different programming languages makes hard for programmers to find bugs and maintenance.

## Proof of Concept
N/A

## Tools Used
Manual revision

## Recommended Mitigation Steps
Add missing Cairo checks into Solidity functions.



## Title (4/6)
Wrong data values written in Cairo event.

## Description
The next events write wrong information into events:

1. file: cairo/handler/src/settlement.cairo
function: receive_cross_chain_msg
[![GitHub code snippet](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L373C1-L381C16)](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L373C1-L381C16)
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

2. file: settlement.cairo
function receive_cross_chain_callback
[![GitHub code snippet](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L432C1-L440C16)](https://github.com/code-423n4/2024-08-chakra/blob/main/cairo/handler/src/settlement.cairo#L432C1-L440C16)
```cairo
self.emit(CrossChainResult {
    cross_chain_settlement_id: cross_chain_msg_id,
    from_address: get_tx_info().unbox().account_contract_address,
    from_chain: to_chain,            <- This should be from_chain, not to_chain
    from_handler: to_handler,        <- Wrong
    to_chain: from_chain,            <- Wrong
    to_handler: from_handler,        <- Wrong
    cross_chain_msg_status: state,
});
```

## Impact
Offchain platforms reading wrong information from blockchain network.

## Proof of Concept
N/A

## Tools Used
Manual revision

## Recommended Mitigation Steps
Fix variables used to populate event fields.



## Title (5/6)
Wrong data values written in Solidity event.

## Description
The next events write wrong information into events:

1. File: solidity/handler/contracts/ChakraSettlementHandler.sol
Function: cross_chain_erc20_settlement
[![GitHub code snippet](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/ChakraSettlementHandler.sol#L212C1-L222C11)](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/ChakraSettlementHandler.sol#L212C1-L222C11)
```solidity
emit CrossChainLocked(
    txid,
    msg.sender,
    to,
    chain,
    to_chain,
    address(this), <- This should be from token addr not this contract addr.
    to_token,
    amount,
    mode
);

// event fields detail:
event CrossChainLocked(
    uint256 indexed txid,
    address indexed from,
    uint256 indexed to,
    string from_chain,
    string to_chain,
    address from_token,
    uint256 to_token,
    uint256 amount,
    SettlementMode mode
);
```

2. File ChakraSettlement.sol
Function: solidity/settlement/contracts/ChakraSettlement.sol
[![GitHub code snippet](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L235C1-L243C11)](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/ChakraSettlement.sol#L235C1-L243C11)
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



## Title (6/6)
Wrongly filling from_token in create_cross_txs struct mapping variable.

## Description
The from_token field is being assigned with handler contract address (this) instead of the from_token: AddressCast.to_uint256(token)

File: solidity/handler/contracts/ChakraSettlementHandler.sol
[![GitHub code snippet](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/ChakraSettlementHandler.sol#L154C1-L164C15)](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/ChakraSettlementHandler.sol#L154C1-L164C15)
```solidity
function cross_chain_erc20_settlement( ... ) external {
    // ...
    
    create_cross_txs[txid] = CreatedCrossChainTx(
        txid,
        chain,
        to_chain,
        msg.sender,
        to,
        address(this), <- This should be token addr not handler addr.
        to_token,
        amount,
        CrossChainTxStatus.Pending
    );

    // ...
}
```

As we can see in struct definition in solidity/handler/contracts/BaseSettlementHandler.sol:
[![GitHub code snippet](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/BaseSettlementHandler.sol#L53C1-L63C6)](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/BaseSettlementHandler.sol#L53C1-L63C6)
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

## Impact
Looks like this field is not being used yet but is being wrongly stored.

## Proof of Concept
N/A

## Tools Used
Manual revision

## Recommended Mitigation Steps
Replace this field with value: AddressCast.to_uint256(token)