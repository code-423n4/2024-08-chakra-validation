## The value of handler_whitelist[chain_name][handler] is not checked

Code Link1: https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L57C9-L57C47

This vulnerability causes the value of the handler to be set to true in the add_handler function, regardless of whether the handler already exists in the handler_whitelist. If the handler is already in the whitelist, this will cause unnecessary duplication of operations, thereby consuming unnecessary gas fees. Although this vulnerability does not directly lead to contract security issues, it will have an adverse impact on the operating cost of the contract, especially when it is called frequently, and users may pay more gas fees unnecessarily.

Original:
```solidity
      handler_whitelist[chain_name][handler] = true;
```

Modified:
```solidity
+     require(!handler_whitelist[chain_name][handler]);
      handler_whitelist[chain_name][handler] = true;
```