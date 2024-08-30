https://github.com/code-423n4/2024-08-chakra/blob/main/solidity/handler/contracts/ERC20CodecV1.sol#L73

for _payload[129:161], _payload[161] is actually out of scope.

    function deocde_transfer(
        bytes calldata _payload
    ) external pure returns (ERC20TransferPayload memory transferPayload) {
        transferPayload.method_id = ERC20Method(uint8(_payload[0]));
        transferPayload.from = abi.decode(_payload[1:33], (uint256));
        transferPayload.to = abi.decode(_payload[33:65], (uint256));
        transferPayload.from_token = abi.decode(_payload[65:97], (uint256));
        transferPayload.to_token = abi.decode(_payload[97:129], (uint256));
        transferPayload.amount = abi.decode(_payload[129:161], (uint256));
    }

should be 
   
    function deocde_transfer(
        bytes calldata _payload
    ) external pure returns (ERC20TransferPayload memory transferPayload) {
        transferPayload.method_id = ERC20Method(uint8(_payload[0]));
        transferPayload.from = abi.decode(_payload[1:32], (uint256));
        transferPayload.to = abi.decode(_payload[33:64], (uint256));
        transferPayload.from_token = abi.decode(_payload[65:96], (uint256));
        transferPayload.to_token = abi.decode(_payload[97:128], (uint256));
        transferPayload.amount = abi.decode(_payload[129:160], (uint256));
    }

