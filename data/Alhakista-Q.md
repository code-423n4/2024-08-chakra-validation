1. Usage of uint256 Type Instead of address in Solidity
In the ChakraSettlementHandler.sol contract, the usage of wrong data type for address type will eventually result in a grevious vulnerability.

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L111-L115

The right data type consistent with solidity standard should be used.