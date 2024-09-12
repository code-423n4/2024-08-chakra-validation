## [L-01] Missing Duplicate check in `add_handler` and `remove_handler` in ChakrasettlementHandler

Lack of duplicate checks in `add_handler` makes redundant while adding already valid handler and removing non valid handler doesn’t make sense.

[ChakraSettlement.sol#L53-#l70](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L53-#L70)

Recommendation:

```solidity
function add_handler(
        string memory chain_name,
        uint256 handler
    ) external onlyOwner {
+				if(!is_valid_handler(chain_name,handler){
	        handler_whitelist[chain_name][handler] = true;
+			  }
}

function remove_handler(
        string memory chain_name,
        uint256 handler
    ) external onlyOwner {
+		    if(is_valid_handler(chain_name,handler){
	        handler_whitelist[chain_name][handler] = false;
+			  }
    }
```

## [L-02] Missing event emissions while calling `add_handler()` and `remove_handler()` as it updates storage

[ChakraSettlement.sol#L53-#l70](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/solidity/handler/contracts/ChakraSettlementHandler.sol#L53-#L70)

Add events for important storage updates 

```solidity

event HandlerAdded (string memory chain,uint256 handler);
event HandlerRemoved (string memory chain,uint256 handler);

function add_handler(
        string memory chain_name,
        uint256 handler
    ) external onlyOwner {
        handler_whitelist[chain_name][handler] = true;
+       emit HandlerAdded(chain_name,handler);
    }

    function remove_handler(
        string memory chain_name,
        uint256 handler
    ) external onlyOwner {
        handler_whitelist[chain_name][handler] = false;
+       emit HandlerRemoved(chain_name,handler);
    }
```

## [L-03] Redudant calling `adding_manager()` if `new_manager` is already a manager and `remove_manager()`  if `old_manager` is not a manager already

[settlement.cairo#L209-#L239](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/settlement.cairo#L209-#L239)

[ckr_btc.cairo#L148-#L161](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/ckr_btc.cairo#L148-#L161)

Lack of duplicate checks in `add_manager()` makes redundant while adding already a manager and removing non valid manager doesn’t make sense.Due to this these functions emit events incorrectly.

Add the below checks

```rust
fn add_manager(ref self: ContractState, new_manager: ContractAddress) -> bool {
            let caller = get_caller_address();
            assert(self.chakra_managers.read(caller) == 1, 'Caller is not a manager');
            assert(caller != new_manager, 'Caller is a manager already');
     +      assert(self.chakra_managers.read(new_manager) != 1, 'new_manager is a manager already');
            self.chakra_managers.write(new_manager, 1);
            self
                .emit(
                    ManagerAdded {
                        operator: caller, new_manager: new_manager, added_at: get_block_timestamp()
                    }
                );
            return self.chakra_managers.read(new_manager) == 1;
        }

fn remove_manager(ref self: ContractState, old_manager: ContractAddress) -> bool {
            let caller = get_caller_address();
            assert(self.chakra_managers.read(caller) == 1, 'Caller is not a manager');
  +         assert(self.chakra_managers.read(old_manager) == 1, 'old_manager is not a manager');
            self.chakra_managers.write(old_manager, 0);
            self
                .emit(
                    ManagerRemoved {
                        operator: caller,
                        old_manager: old_manager,
                        removed_at: get_block_timestamp()
                    }
                );
            return self.chakra_managers.read(old_manager) == 0;
        }
```