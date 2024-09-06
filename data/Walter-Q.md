## Improper Nonce Management in ``cross_chain_erc20_settlement`` Function
The function ``cross_chain_erc20_settlement`` in the ``ChakraSettlementHandler`` contract contains an issue where the nonce is incremented before the transaction is fully created and saved. The nonce is updated immediately upon entering the function, without confirming the successful creation or saving of the transaction.
```solidity
function cross_chain_erc20_settlement(
        string memory to_chain,
        uint256 to_handler,
        uint256 to_token,
        uint256 to,
        uint256 amount
    ) external {
        ...

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

       ...
    }
```
This can result in the first nonce value for each ``msg.sender`` being skipped, as it sacrifices the initial nonce without it being linked to an actual transaction. As a consequence, the contract consistently uses ``nonce + 1`` for future transactions, leading to inefficiencies and a potential waste of the first nonce.

### Recommendation
Reorder the function to increment the nonce only after the transaction has been created and saved successfully. This ensures that ``nonces`` are managed correctly and avoids unnecessary gaps in nonce usage.