## [G-1] Increased gas spendings due to unused functions and redundant code
Many unused functions and redundant code across the codebase. For instance, most of the `MessageV1Codec` library functionality is never used. For instance:

```solidity
import {AddressCast} from "contracts/libraries/AddressCast.sol";
...
    using AddressCast for address;
    using AddressCast for bytes32;
```
[MessageV1Codec.sol#L5](https://github.com/code-423n4/2024-08-chakra/blob/f61c899c22492bdf5bdcb07cdb62ea9b4cd38825/solidity/handler/contracts/libraries/MessageV1Codec.sol#L5), [MessageV1Codec.sol#L8-L9](https://github.com/code-423n4/2024-08-chakra/blob/f61c899c22492bdf5bdcb07cdb62ea9b4cd38825/solidity/handler/contracts/libraries/MessageV1Codec.sol#L8-L9)

## [NC-1] Different logic between Solidity and Cairo contract increase the risk of issues in future development
The logic between Solidity and Cairo contract is different, sometimes critically.

**Recommended Mitigation Steps**
Make sure to follow the same flow and design patterns between Solidity and Cairo contracts that are intended to work the same.

## [NC-2] Multiple typos across the codebase

- reuiqred -> required [BaseSettlement.sol#L138](https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/settlement/contracts/BaseSettlement.sol#L138);
- Unknow -> Unknown, Unkown -> Unknown in multiple instances across the codebase;
- Arppvoe -> Approve [ERC20Payload.sol#L11](https://github.com/code-423n4/2024-08-chakra/blob/f61c899c22492bdf5bdcb07cdb62ea9b4cd38825/solidity/handler/contracts/libraries/ERC20Payload.sol#L11);
- encodedPaylaod -> encodedPayload [ERC20CodecV1.sol#L38](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ERC20CodecV1.sol#L38);

## [NC-3] Wrong event parameters in `cross_chain_erc20_settlement`
The `cross_chain_erc20_settlement` function of the `ChakraSettlementHandler` contract the following event on success:
```solidity
emit CrossChainLocked(txid, msg.sender, to, chain, to_chain, address(this), to_token, amount, mode);
```
[ChakraSettlementHandler.sol#L218](https://github.com/code-423n4/2024-08-chakra/blob/f61c899c22492bdf5bdcb07cdb62ea9b4cd38825/solidity/handler/contracts/ChakraSettlementHandler.sol#L218)

The `CrossChainLocked` event is defined as:
```solidity
event CrossChainLocked(uint256 txid,
            address from,
            uint256 to,
            string from_chain,
            string to_chain,
            address from_token,
            uint256 to_token,
            uint256 amount,
            SettlementMode mode) 
```
[BaseSettlementHandler.sol#L41-L51](https://github.com/code-423n4/2024-08-chakra/blob/f61c899c22492bdf5bdcb07cdb62ea9b4cd38825/solidity/handler/contracts/BaseSettlementHandler.sol#L41-L51)

According to the [docs](https://github.com/code-423n4/2024-08-chakra/blob/f61c899c22492bdf5bdcb07cdb62ea9b4cd38825/solidity/handler/contracts/libraries/ERC20Payload.sol#L25), `from_token` is *The token address on the source chain.* However, instead of emitting the `token` storage variable, the event emits the address of a handler contract (`address(this)`). 

**Recommended Mitigation Steps**
Replace `address(this)` in [ChakraSettlementHandler.sol#L218](https://github.com/code-423n4/2024-08-chakra/blob/f61c899c22492bdf5bdcb07cdb62ea9b4cd38825/solidity/handler/contracts/ChakraSettlementHandler.sol#L218) with `token`.

## [L-1] Possible loss of funds due to the lack of handler validation in `cross_chain_erc20_settlement`

The lack of handler validation in `cross_chain_erc20_settlement` in 
Possible lock or burn of caller's funds, depending on the settlement mode. [ChakraSettlementHandler.sol#L111](https://github.com/code-423n4/2024-08-chakra/blob/f61c899c22492bdf5bdcb07cdb62ea9b4cd38825/solidity/handler/contracts/ChakraSettlementHandler.sol#L111)

**Recommended Mitigation Steps**
Add a check whether the handler is whitelisted to the `cross_chain_erc20_settlement` function.

## [L-2] Mismatched transaction IDs between Cairo and Solidity contracts due to different nonce calculations

In Sodity contract's `send_cross_chain_msg` function, the nonce is first increased and then used for encoding the transaction. However, in Cairo, the nonce (named as `tx_count` and `msg_count`) in the same function is first used and only then increased.

This influences cross chain transfers' by encoding wrong values to the payload potentially leading to a loss of funds.
If `msg_count` does not match the number of transactions `tx_count` on both chains, this might create duplicate IDs.

**Recommended Mitigation Steps**
Use the same pattern in both Cairo and Solidity contracts.

## [L-3] The protocol does not support any other token than ERC20 even though claimed different

According to the docs provided: *The contract only accepts valid payload types (in this case, only ERC20 payloads).*

However, the Scoping Q&A section states that ERC20, ERC721, ERC777, and ERC1155 tokens should be all supported by the protocol. [ChakraSettlementHandler.sol#L318-L354](https://github.com/code-423n4/2024-08-chakra/blob/f61c899c22492bdf5bdcb07cdb62ea9b4cd38825/solidity/handler/contracts/ChakraSettlementHandler.sol#L318-L354)

**Recommended Mitigation Steps**
Edit the documendation or implement the support for ERC721 tokens.

## [L-4] `send_cross_chain_msg` can be called by anybody spamming the validators with invalid events

The `CrossChainMsg` event is emitted on source chain so that the validators can scan it and invoke `receive_cross_chain_msg` on destination chain.

According to the NatSpec comments for the `send_cross_chain_msg` function in Cairo handler source code: `only handler can call this function`. 
```solidity
// @notice send cross chain message, only handler can call this function
 
```
[settlement.cairo#L279](https://github.com/code-423n4/2024-08-chakra/blob/f61c899c22492bdf5bdcb07cdb62ea9b4cd38825/cairo/handler/src/settlement.cairo#L279)
However, there is no such check in both Solidity and Cairo contracts.

Even though, the handler is checked later in `handler.receive_cross_chain_msg` on the destination chain, it will still emit the failed status event `CrossChainMsgStatus.Failed`.

**Recommended Mitigation Steps**
Add proper check to ensure only the handler can call the `send_cross_chain_msg` function.