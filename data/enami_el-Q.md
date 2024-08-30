### Inadequate Validation of Constructor Parameters

#### Severity: Low

#### Description:
The `_Settlement_handler_init` function lacks validation checks for the input parameters, particularly `_chain` and `_token`. Without proper validation, there is a risk of incorrect initialization by the owner, which could lead to potential issues, such as using an invalid or unsupported chain or a zero address for the token.

- **_chain**: The chain parameter is a string and could potentially be set to an invalid or unsupported value, leading to operational issues.
- **_token**: The `_token` address could be set to the zero address, which would cause failures in operations that expect a valid ERC20 token address.

#### Part code:

``` solidity 
    function _Settlement_handler_init(
        address _owner,
        SettlementMode _mode,
        address _token,
        address _verifier,
        string memory _chain,
        address _settlement
    ) public {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();
        settlement = ISettlement(_settlement);
        verifier = ISettlementSignatureVerifier(_verifier);
        mode = _mode;
        token = _token;
        chain = _chain;
    }
```
link: https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/BaseSettlementHandler.sol
#### Recommendation:
1. **Chain Validation**:
   - Implement a validation mechanism for the `_chain` parameter. One approach could be to maintain a mapping of supported chains, allowing the owner to select only from the available options.
   - Alternatively, add a check to ensure that the provided chain value is valid and supported.

   ```solidity
   mapping(string => bool) public supportedChains;

   require(supportedChains[_chain], "Unsupported chain.");
   ```

2. **Token Address Validation**:
   - Add a check to ensure that the `_token` address is not set to the zero address.

   ```solidity
   require(_token != address(0), "Invalid token address.");
   ```
### Typo in `CrossChainTxStatus` Enum

#### Severity: Informational

#### Description:
The `CrossChainTxStatus` enum has a typo, with the value "Unknow" instead of "Unknown." This can lead to confusion.

#### Code :

``` solidity
    enum HandlerStatus {
        Unknow,
        Pending,
        Success,
        Failed
    }
```
https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/BaseSettlementHandler.sol#L101-L102
#### Recommendation:
Rename `Unknow` to `Unknown` for clarity and consistency.





###  No Check for Unique `txid` in `create_cross_txs` Mapping

#### Severity: Low

#### Description:
The `create_cross_txs` mapping stores `CreatedCrossChainTx` by transaction ID (`txid`). There is no check to ensure that the `txid` is unique, which could lead to overwriting existing transactions and loss of data.

#### Code

``` solidity
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

        {
            // Save the cross chain tx
            create_cross_txs[txid] = CreatedCrossChainTx(
                txid,
                chain,
                to_chain,
                msg.sender,
                to,
                address(this),
                to_token,
                amount,
                CrossChainTxStatus.Pending
            );
        }
```
https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/ChakraSettlementHandler.sol#L138-L165
#### Recommendation:
Implement a check to ensure that the `txid` is unique before creating a new cross-chain transaction.

```solidity
require(create_cross_txs[txid].txid == 0, "Transaction ID already exists");
```