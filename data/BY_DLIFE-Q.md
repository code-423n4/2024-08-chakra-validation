## Removing unnecessary parameters can also avoid unexpected errors to a certain extent[AddressCast.sol::to_bytes()]

Code Link1: https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/libraries/AddressCast.sol#L32-L36

Code Link2: https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/settlement/contracts/libraries/AddressCast.sol#L55-L61

As we all know, the length of an address is 20 bytes. In this function, the caller needs to pass in the length of the address, which is obviously unnecessary. This not only wastes the execution efficiency of the code, but also increases the consumption of gas fees. What's more serious is that the incorrect address length parameter passed in may cause address parsing errors, thus causing a series of problems.

## recommendation
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