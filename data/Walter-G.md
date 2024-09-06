## Redundant Variable Assignment in ``receive_cross_chain_msg`` Function
In the ``receive_cross_chain_msg`` function of the ``ChakraSettlement`` contract, the variable ``CrossChainMsgStatus`` status is explicitly set to ``CrossChainMsgStatus.Failed`` before checking the result of the cross-chain message handling:
```
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
            ...

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
This assignment is unnecessary because the status of the transaction can be directly derived from ``receive_cross_txs[txid].status``. The redundant status initialization adds no additional value and can be safely removed to simplify the code and spend less gas each ``receive_cross_chain_msg`` call.

### Recommendation
```

        ...

        if (result == true) {
            receive_cross_txs[txid].status = CrossChainMsgStatus.Success;
        } else {
            receive_cross_txs[txid].status = CrossChainMsgStatus.Failed;
        }

        emit CrossChainHandleResult(
            txid,
            receive_cross_txs[txid].status,
            contract_chain_name,
            from_chain,
            address(to_handler),
            from_handler,
            payload_type
        );
```