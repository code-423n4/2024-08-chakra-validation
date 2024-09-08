## Vulnerability details
In `ChakraSettlement::receive_cross_chain_msg`, the struct `receive_cross_txs` is bad updated because in the sixth field, the contract updates the struct with `address(this)`, but instead, according to the struct `ReceivedCrossChainTx`, in the sixth field the value updated should be `to_handler`. 

As we can see, `address(this)` would be the address of the `ChakraSettlement`, but instead, in that field, there should be the address of the handler in the destination chain. 

## PoC
Here below there is  a test (done with Foundry), where we can see that this struct is bad updated. 

```solidity
function test_receive_cross_txsIsBadUpdated() public {
//Note: the required validators is setted to 1, all the contracts have been initializated and the operator (SettlementHandler) has been added to chakra token in the 'setUp' file.
uint256 privateKeyValidator1 = 0x12D; 
address validator1 = vm.addr(privateKeyValidator1);

address UserAccount1 = makeAddr("UserAccount1");

//Here owner Adds managers to both chains (arbitrum and base)
vm.selectFork(arbFork);
vm.startPrank(owner);
settlementSignatureVerifierArb.add_manager(bob);
vm.selectFork(baseFork);
settlementSignatureVerifierBase.add_manager(bob);
vm.stopPrank(); 

//Here owner Adds validators to both chains (arbitrum and base)
vm.startPrank(bob);
vm.selectFork(arbFork);
settlementSignatureVerifierArb.add_validator(validator1);
vm.selectFork(baseFork);
settlementSignatureVerifierBase.add_validator(validator1);
vm.stopPrank();

//Here owner adds valid base handler on Arbitrum
vm.selectFork(arbFork);
vm.startPrank(owner); 
chakraSettlementHandlerArb.add_handler("Base", uint160(address(chakraSettlementHandlerBase)));
vm.stopPrank();

vm.startPrank(UserAccount1);
vm.selectFork(baseFork);

//payload 
//Here there is a anticipated calculation of the cross chain tx payload, that will be used later in this test.
bytes memory payload;
uint256 crosschain_counter_msg = 1; 
uint256 nonce = 1; 
uint256 cross_chain_msg_id = uint256(keccak256(abi.encodePacked(crosschain_counter_msg,address(chakraSettlementHandlerBase), UserAccount1,nonce)));

ERC20TransferPayload memory _payload = ERC20TransferPayload(
ERC20Method.Transfer, 
AddressCast.to_uint256(UserAccount1), 
uint160(UserAccount1),
AddressCast.to_uint256(address(chakraToken_base)), //from token 
uint160(address(chakraToken_arb)), //to token
100e18
);

Message memory cross_chain_msg = Message(
cross_chain_msg_id, 
PayloadType.ERC20, 
codecBase.encode_transfer(_payload)
);

payload = MessageV1Codec.encode(cross_chain_msg);

//Give 100 chakra token to user on base
deal(address(chakraToken_base), UserAccount1, 100e18); 
//Approve the handler 
IERC20(address(chakraToken_base)).approve(address(chakraSettlementHandlerBase), 100e18);

//The user calls the base handler to perform his cross chain tx and he locks 100 chakra tokens on base
chakraSettlementHandlerBase.cross_chain_erc20_settlement("Arbitrum", uint160(address(chakraSettlementHandlerArb)), uint160(address(chakraToken_arb)), uint160(UserAccount1), 100e18);
vm.stopPrank();

uint256 nonce_manager = 1; 
uint8 sign_type = 0; 
uint256 txId = uint256(keccak256(abi.encodePacked("Base", "Arbitrum", UserAccount1,uint160(address(chakraSettlementHandlerBase)),uint160(address(chakraSettlementHandlerArb)), nonce_manager)));

vm.startPrank(validator1);
//The validator signs the message and accepts the transaction
(uint8 v,bytes32 r, bytes32 s) = vm.sign(privateKeyValidator1, 0xee0e8fab5358d4376a87db6429a34102e02ff2a4188567c4d584f041dfe6d9ea);//Here we can note a byte value, it is the message_hash and has been retrieved using the Foundry console with the command -vvv
bytes memory signature = abi.encodePacked(r, s, v);

vm.selectFork(arbFork);
//The validator calls 'receive_cross_chain_msg' on the destination chain (arbitrum)
chakraSettlementArb.receive_cross_chain_msg(txId, "Base", uint160(UserAccount1), uint160(address(chakraSettlementHandlerBase)), address(chakraSettlementHandlerArb), PayloadType.ERC20, payload, sign_type, signature);

(, , , , , address toHandler , ,) = chakraSettlementArb.receive_cross_txs(txId);
//The value 'to_handler' is not effectively the handler on the arbitrum chain, but it is the settlement contract
assertEq(toHandler, address(chakraSettlementArb));
}
```

## Mitigation review
In the sixth field of the struct `ReceivedCrossChainTx`, instead of using `address(this)`, use `to_handler`.