
# QA for Chakra

## Table of Contents

| Issue ID | Description |
| -------- | ----------- |
| [QA-01](#qa-01-incorrect-to_handler-value-set-in-receive_cross_txs-during-cross-chain-message-reception) | Incorrect `to_handler` Value Set in `receive_cross_txs` During Cross-Chain Message Reception |
| [QA-02](#qa-02-incorrect-from_token-value-set-in-createdcrosschaintx-struct-in-cross_chain_erc20_settlement-during-cross-chain-message-creation) | Incorrect `from_token` Value Set in `CreatedCrossChainTx` struct in `cross_chain_erc20_settlement` During Cross-Chain Message Creation |
| [QA-03](#qa-03-incorrect-from_token-parameter-in-crosschainlocked-event-emission-in-cross_chain_erc20_settlement) | Incorrect `from_token` Parameter in `CrossChainLocked` Event Emission in `cross_chain_erc20_settlement` |
| [QA-04](#qa-04-cross-chain-ssettlement-id-not-converted-to-u256-in-crosschainmsg-event-emitted-by-starknet-handlers) | Cross-Chain sSettlement ID not converted to `u256` in `CrossChainMsg` event emitted by Starknet handlers |
| [QA-05](#qa-05-inability-to-customize-chakratoken-decimals-during-deployment-on-starknet) | Inability to Customize `ChakraToken` Decimals During Deployment on Starknet |
| [QA-06](#qa-06-starknet-handlers-revert-when-receiving-cross-chain-messages-from-unwhitelisted-handlers-instead-of-returning-false-which-can-lead-to-issues) | Starknet Handlers Revert When Receiving Cross-Chain Messages from Unwhitelisted Handlers Instead of Returning False Which Can Lead to Issues |


## [QA-01] Incorrect `to_handler` Value Set in `receive_cross_txs` During Cross-Chain Message Reception
### Impact
In the `ChakraSettlement` Solidity contract, when a cross-chain message is received, the `ReceivedCrossChainTx` structure is populated. However, there is an issue where the 6th argument, which corresponds to the handler address (`to_handler`) responsible for processing the cross-chain message, is incorrectly set to the address of the settlement contract (`address(this)`) instead of the intended handler address.
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
    // --SNIP
    receive_cross_txs[txid] = ReceivedCrossChainTx(
        txid,
        from_chain,
        contract_chain_name,
        from_address,
        from_handler,
>>>        address(this),
        payload,
        CrossChainMsgStatus.Pending
    );
    // --SNIP
}
```

### Recommended Mitigation Steps

Update the 6th argument of the `ReceivedCrossChainTx` structure to correctly reference the `to_handler` parameter instead of `address(this)`:
```diff
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
    // --SNIP
    receive_cross_txs[txid] = ReceivedCrossChainTx(
        txid,
        from_chain,
        contract_chain_name,
        from_address,
        from_handler,
-       address(this),
+       to_handler,
        payload,
        CrossChainMsgStatus.Pending
    );
    // --SNIP
}
```

## [QA-02] Incorrect `from_token` Value Set in `CreatedCrossChainTx` struct in `cross_chain_erc20_settlement` During Cross-Chain Message Creation
### Impact
In the `ChakraSettlementHandler` Solidity contract, when a cross-chain message is created, the `CreatedCrossChainTx` structure is populated. However, there is an issue where the 6th argument, which corresponds to the token address on the source chain (`from_token`), is incorrectly set to the address of the handler contract (`address(this)`) instead of the intended token address.
```solidity
function cross_chain_erc20_settlement(
    string memory to_chain,
    uint256 to_handler,
    uint256 to_token,
    uint256 to,
    uint256 amount
) external {
    // --SNIP
    create_cross_txs[txid] = CreatedCrossChainTx(
        txid,
        chain,
        to_chain,
        msg.sender,
        to,
>>>        address(this),
        to_token,
        amount,
        CrossChainTxStatus.Pending
    );
    // --SNIP
}
```

### Recommended Mitigation Steps

Update the 6th argument of the `CreatedCrossChainTx` structure to correctly reference the `from_token` parameter instead of `address(this)`:
```diff
function cross_chain_erc20_settlement(
    string memory to_chain,
    uint256 to_handler,
    uint256 to_token,
    uint256 to,
    uint256 amount
) external {
    // --SNIP
    create_cross_txs[txid] = CreatedCrossChainTx(
        txid,
        chain,
        to_chain,
        msg.sender,
        to,
-       address(this),
+       from_token,
        to_token,
        amount,
        CrossChainTxStatus.Pending
    );
    // --SNIP
}
```

## [QA-03] Incorrect `from_token` Parameter in `CrossChainLocked` Event Emission in `cross_chain_erc20_settlement`

### Impact
In the `ChakraSettlementHandler` Solidity contract, the `CrossChainLocked` event is emitted when a cross-chain message is created. However, there is an issue with the 6th parameter, `from_token`, which should represent the token address on the source chain. Instead, it is incorrectly set to the handler's address (`address(this)`), which could lead to incorrect event logs and confusion when tracking the source token of the transaction.
```solidity
function cross_chain_erc20_settlement(
    string memory to_chain,
    uint256 to_handler,
    uint256 to_token,
    uint256 to,
    uint256 amount
) external {
    // --SNIP
    emit CrossChainLocked(
        txid,
        msg.sender,
        to,
        chain,
        to_chain,
>>>        address(this), 
        to_token,
        amount,
        mode
    );
}
```

### Recommended Mitigation Steps

Update the 6th parameter in the `CrossChainLocked` event to correctly reflect the token address (`from_token`)
```diff
function cross_chain_erc20_settlement(
    string memory to_chain,
    uint256 to_handler,
    uint256 to_token,
    uint256 to,
    uint256 amount
) external {
    // --SNIP
    emit CrossChainLocked(
        txid,
        msg.sender,
        to,
        chain,
        to_chain,
-       address(this), 
+       from_token
        to_token,
        amount,
        mode
    );
}
```

## [QA-04] Cross-Chain sSettlement ID not converted to `u256` in `CrossChainMsg` event emitted by Starknet handlers

### Impact
When processing cross-chain ERC20 messages, the settlement contract emits the `CrossChainMsg` event to notify Chakra nodes of the new message. The first argument of this event is the cross-chain settlement ID, which is generated as a `felt252` type. However, this ID is not converted to `u256` before emitting the event:
```rs
// settlement

fn send_cross_chain_msg(ref self: ContractState, to_chain: felt252, to_handler: u256, payload_type :u8,payload: Array<u8>,) -> felt252 {
    // --SNIP
    let cross_chain_settlement_id = LegacyHash::hash(get_tx_info().unbox().transaction_hash, self.tx_count.read());
    // --SNIP

    self.emit(CrossChainMsg {
>>>        cross_chain_settlement_id: cross_chain_settlement_id, 
        from_address: get_tx_info().unbox().account_contract_address,
        from_chain: from_chain, to_chain: to_chain, from_handler: from_handler, to_handler: to_handler, payload_type: payload_type, payload: payload
    });
}
```
While EVM-based chains do not support the `felt252` type, and the ID will likely be interpreted as a number, it is advisable to convert the settlement ID to `u256`

### Recommended Mitigation Steps
Convert the `cross_chain_settlement_id` to `u256` when emitting the `CrossChainMsg` event:
```diff
fn send_cross_chain_msg(ref self: ContractState, to_chain: felt252, to_handler: u256, payload_type :u8,payload: Array<u8>,) -> felt252 {
    // --SNIP
    let cross_chain_settlement_id = LegacyHash::hash(get_tx_info().unbox().transaction_hash, self.tx_count.read());
    // --SNIP

    self.emit(CrossChainMsg {
-       cross_chain_settlement_id: cross_chain_settlement_id, 
+       cross_chain_settlement_id: cross_chain_settlement_id.into(),
        from_address: get_tx_info().unbox().account_contract_address,
        from_chain: from_chain, to_chain: to_chain, from_handler: from_handler, to_handler: to_handler, payload_type: payload_type, payload: payload
    });
}
```

## [QA-05] Inability to Customize `ChakraToken` Decimals During Deployment on Starknet
### Impact
The ChakraToken is designed to have customizable decimals upon deployment, as confirmed by the sponsor and demonstrated in the Solidity implementation:
```solidity
contract ChakraToken is ERC20Upgradeable, TokenRoles, IERC20Mint, IERC20Burn {
    uint8 set_decimals;
    function initialize( address _owner, address _operator, string memory _name, string memory _symbol, uint8 _decimals) public initializer {
        __TokenRoles_init(_owner, _operator);
        __ERC20_init(_name, _symbol);
>>>        set_decimals = _decimals;
    }

    function decimals() public view override returns (uint8) {
        return set_decimals;
    }
}
```
However, on Starknet, the Chakra token is hardcoded to `18` decimals (the default value), with no option to specify a custom decimal value during deployment:
```rs
mod ckrBTC {
    // --SNIP
    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        self.ownable.initializer(owner);

        let name = "ckrBTC";
        let symbol = "CBTC";

        self.erc20.initializer(name, symbol);
        self.chakra_managers.write(owner, 1);
    }
}
```
This limitation may result in inconsistencies between the Solidity-based Chakra tokens and those deployed on Starknet, especially if a non-default decimal value is required.

### Recommended Mitigation Steps
Consider overriding the `decimals` method in the Cairo implementation of the Chakra token. You can add the following code to `ckr_btc.cairo`:
```rs
#[external(v0)]
impl ERC20MetadataImpl of interface::IERC20Metadata<ContractState> {
    fn decimals(self: @ContractState) -> u8 {
        // Change the `8` below to the desired number of decimals
        8
    }
}
```
Alternatively, you can follow the [storage approach](https://docs.openzeppelin.com/contracts-cairo/0.9.0/erc20#the_storage_approach) outlined in the OpenZeppelin documentation

## [QA-06] Starknet Handlers Revert When Receiving Cross-Chain Messages from Unwhitelisted Handlers Instead of Returning False Which Can Lead to Issues

### Impact
When Starknet handlers receive cross-chain messages or callbacks from unwhitelisted handlers, they revert instead of returning `false` like implemented in Solidity
```rs
fn receive_cross_chain_msg(ref self: ContractState, cross_chain_msg_id: u256, from_chain: felt252, to_chain: felt252,
    from_handler: u256, to_handler: ContractAddress, payload: Array<u8>) -> bool{
    
    assert(to_handler == get_contract_address(),"error to_handler");
    assert(self.settlement_address.read() == get_caller_address(), "not settlement");
>>>    assert(self.support_handler.read((from_chain, from_handler)) && 
            self.support_handler.read((to_chain, contract_address_to_u256(to_handler))), "not support handler");
}
```
This approach poses a problem: if a cross-chain message from a whitelisted handler is sent to Starknet, but in the interim, the source handler becomes unwhitelisted, the Starknet handler will revert when processing the message. This results in a deadlock where the cross-chain message cannot be processed, leaving it in an unresolved state.

The correct handling should involve emitting a `CrossChainHandleResult` with a `Failed` status, allowing the source chain to manage the issue in the callback, like how it is implemented in Solidity.


### Recommended Mitigation Steps
Consider modifying the Starknet handler to return `false` when receiving a cross-chain message from an unwhitelisted handler, rather than reverting.