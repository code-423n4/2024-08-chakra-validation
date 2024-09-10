# `BaseSettlementHandler` Contract Inherits `AccessControlUpgradeable` But Never Uses It

## Explanation
The `BaseSettlementHandler` contract inherits from `AccessControlUpgradeable`, which provides role-based access control features. However, the contract does not use any methods provided by `AccessControlUpgradeable`, nor does it grant the `DEFAULT_ADMIN_ROLE` to any address. This unnecessary inheritance increases the contract's bytecode size, making it more complex and potentially more expensive to deploy and interact with. Moreover, the lack of granted roles could lead to confusion or improper security assumptions about access control in the contract.

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/BaseSettlementHandler.sol#L21


# Lack of `toEthSignedMessageHash()` Usage in Protocol

## Explanation

The protocol does not utilize the `toEthSignedMessageHash()` function when handling user-signed messages. This function is part of the ERC-191 standard, which adds a prefix to signed messages (such as "\x19Ethereum Signed Message:\n") to ensure the message is clearly identified as an Ethereum-signed message. The absence of this step could lead to user confusion or manipulation, as users might unknowingly sign raw data that could be interpreted differently than intended. This increases the risk of phishing attacks or other malicious activities where a user's signature could be misused due to a lack of clear message formatting. 

Adding this prefix is a best practice in Ethereum-based protocols to safeguard users from signing misleading or potentially harmful messages.

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/SettlementSignatureVerifier.sol#L180

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/SettlementSignatureVerifier.sol#L114


# Unused Methods in `SettlementSignatureVerifier.sol`

## Explanation

The methods of the `handler/contracts/SettlementSignatureVerifier.sol` contract are never utilized in the handler contracts, with only the address being saved in `BaseSettlementHandler`. 

Initially, the protocol likely intended to verify the signature inputs in the `ChakraSettlementHandler::receive_cross_chain_msg` and `ChakraSettlementHandler::receive_cross_chain_callback` functions. However, the signature inputs in these functions are currently commented out, leaving the signature verification functionality unused.

The `SettlementSignatureVerifier.sol` contract was presumably designed to ensure the integrity of cross-chain communications by verifying signatures. However, with the signature verification logic disabled in the core functions, this mechanism is bypassed, reducing the effectiveness of the intended security measures. The absence of signature validation poses a potential risk, as there is no check to authenticate messages or callbacks received during cross-chain transactions.

https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/SettlementSignatureVerifier.sol