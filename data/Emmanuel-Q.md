## L-001
## Title
Protocol might be susceptible to block reorgs

## Proof of Concept
For a CCTX between an EVM chainA and Starknet, If the validators signs the message immediately the CrossChainMsg gets emitted, receive_cross_chain_msg could be called before the block settlement period of the source chain.
In the case of a reorg on the source chain, the user's tx can get removed and refunded on the source chain, but will still be able to claim on dest chain. 
This is double spending.