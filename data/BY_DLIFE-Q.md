## Removing unnecessary parameters can also avoid unexpected errors to a certain extent[AddressCast.sol::to_bytes()]

Code Link1: https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/libraries/AddressCast.sol#L32-L36

Code Link2: https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/libraries/AddressCast.sol#L55-L61

As we all know, the length of an address is 20 bytes. In this function, the caller needs to pass in the length of the address, which is obviously unnecessary. This not only wastes the execution efficiency of the code, but also increases the consumption of gas fees. What's more serious is that the incorrect address length parameter passed in may cause address parsing errors, thus causing a series of problems.

**recommendation**
The suggested improvement is: remove the `_size` parameter and declare it explicitly in the function body with a value of `20`.
The improved code is:
```solidity
    function to_bytes(
        bytes32 _addressBytes32,
        // uint256 _size
    ) internal pure returns (bytes memory result) {
        // if (_size == 0 || _size > 32)
           // revert AddressCast_InvalidSizeForAddress();
        // result = new bytes(_size);
        result = new bytes(20);
        unchecked {
            // uint256 offset = 256 - _size * 8;
            uint256 offset = 256 - 20 * 8;
            assembly {
                mstore(add(result, 32), shl(offset, _addressBytes32))
            }
        }
    }
```


## Missing checks for address(0) when assigning values to address state variables

Code Link1: https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/BaseSettlementHandler.sol#L123-L124

This function is called in `ChakraSettlementHandler.sol::initialize()`. The `initialize()` function is modified by the `initializer` decorator, so that `initialize()` can only be executed once, so it is necessary to check whether the parameters are correct, otherwise they cannot be modified once an error occurs.

Original：

```solidity
        settlement = ISettlement(_settlement);
        verifier = ISettlementSignatureVerifier(_verifier);
```

Modified:
```solidity
+       require(_settlement != address(0));
+       require(_verifier!= address(0));
        settlement = ISettlement(_settlement);
        verifier = ISettlementSignatureVerifier(_verifier);
```

Code Link2: https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L100

Reason: Same as above

Original:
```solidity
      codec = IERC20CodecV1(_codec);
```

Modified:
```solidity
+     require(_codec != address(0));
      codec = IERC20CodecV1(_codec);
```

Code Link3: https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/TokenRoles.sol#L19-L23

Reason: Same as above

Original:
```solidity
      _grantRole(OPERATOR_ROLE, _operator);
```

Modified:
```solidity
+     require(_operator!= address(0));
      _grantRole(OPERATOR_ROLE, _operator);
```

Code Link4: https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/TokenRoles.sol#L31-L34

Reason: Same as above

Original:
```solidity
      _grantRole(OPERATOR_ROLE, newOperator);
```

Modified:
```solidity
+     require(newOperator!= address(0));
      _grantRole(OPERATOR_ROLE, newOperator);
```