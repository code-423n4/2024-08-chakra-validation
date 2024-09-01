# [L-01] Typographical Error in Multiple Contracts
In ERC20Payload.sol, the enum ERC20Method contains an element labeled "Unkown", which appears to be a typographical error. The correct spelling should be "Unknown." This mistake can lead to confusion and misunderstandings among developers and users interacting with the code. Similarly, in both the BaseSettlementHandler and ChakraSettlementHandler contracts, the term "Unknow" is incorrectly used in enums. This is not a valid English word and should be corrected to "Unknown" to ensure clarity and maintain professionalism in the codebase. 

```solidity
enum ERC20Method {
    Unkown, // 0: Unknown method (also serves as default)  
    Transfer, // 1: Transfer tokens from one address to another
    Arppvoe, // 2: Approve spending of tokens (Note: there's a typo, should be "Approve")
    TransferFrom, // 3: Transfer tokens on behalf of another address
    Mint, // 4: Create new tokens
    Burn // 5: Destroy existing tokens
}

enum TxStatus {
        Unknow,    
        Pending,
        Minted,
        Burned,
        Failed
    }

enum HandlerStatus {
        Unknow,       
        Pending,
        Success,
        Failed
    }
```

Recommendation: Update all instances of "Unkown" and "Unknow" to "Unknown" in the affected contracts to prevent any potential confusion and to adhere to proper English spelling standards.



# [L-02] Use of _disableInitializers() Function in Upgradeable Contracts
The ChakraTokenUpgrade and other upgradable contracts are missing a constructor with the proper annotation to prevent vulnerabilities associated with uninitialized contracts. In the context of upgradeable contracts, it's important to use a constructor to disable initializers, ensuring the implementation contract cannot be initialized directly.
Without this constructor and annotation, there is a risk that the implementation contract could be initialized by an unauthorized party. This could lead to unintended behavior or security vulnerabilities, such as unauthorized minting or burning of tokens.

Recommendation:
Add the following constructor to the contract to disable initializers and prevent the implementation contract from being initialized
```solidity
/// @custom:oz-upgrades-unsafe-allow constructor
constructor() {
   _disableInitializers();
}
```

