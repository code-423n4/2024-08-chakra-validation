1: Misleading Assertion Message

Description:
The assertion message in the u8_array_to_u256 function is misleading. It states "too large" when the input array's length is not equal to 32, but this message doesn't accurately describe the error condition for inputs that are too small.

Code reference:
```
  assert(arr.len() == 32, 'too large');
```
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/utils.cairo#L330C3-L330

Impact:
This bug can lead to confusion for developers using the function, especially when debugging issues related to input size. It may cause developers to mistakenly assume that only large inputs are problematic, potentially overlooking errors caused by inputs that are too small.

Recommendation:
Change the assertion message to accurately reflect both possible error conditions:

```
assert(arr.len() == 32, 'input must be exactly 32 bytes');
```
This new message clearly states the expected input size, covering both too large and too small scenarios.


2. Lack of existence check in Manager removal function

Description

The `remove_manager` function does not verify the existence of the old manager before attempting to remove them. 

```
 fn remove_manager(ref self: ContractState, old_manager: ContractAddress) -> bool {
            let caller = get_caller_address();
            assert(self.chakra_managers.read(caller) == 1, 'Caller is not a manager');
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
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/settlement.cairo#L260-L274

Current behavior:
1. The function checks if the caller is a manager.
2. It directly writes a 0 to the `chakra_managers` mapping for the `old_manager` address.
3. It emits a `ManagerRemoved` event.
4. It returns true if the `old_manager` address now has a value of 0 in the `chakra_managers` mapping.

The problem with this approach is that it will "succeed" even if the `old_manager` was never a manager in the first place. 

Impact
- Misleading Events: The contract will emit a `ManagerRemoved` event even if no manager was actually removed, potentially confusing off-chain systems or users monitoring these events.

2. False Success Indication: The function will return `true` even if it didn't actually remove a manager, as long as the `old_manager` address has a value of 0 in the `chakra_managers` mapping after the operation.

3. Unnecessary State Changes and Gas Costs: Even if the `old_manager` wasn't a manager, the function still performs a state write operation, consuming gas unnecessarily.

Recommendation

To address this issue, the function should be modified to include an existence check before proceeding with the removal process. Here's a suggested modification:

```
fn remove_manager(ref self: ContractState, old_manager: ContractAddress) -> bool {
    let caller = get_caller_address();
    assert(self.chakra_managers.read(caller) == 1, 'Caller is not a manager');
    
    // Add this check
    assert(self.chakra_managers.read(old_manager) == 1, 'Address is not a manager');

    self.chakra_managers.write(old_manager, 0);

    self.emit(
        ManagerRemoved {
            operator: caller,
            old_manager: old_manager,
            removed_at: get_block_timestamp()
        }
    );

    return self.chakra_managers.read(old_manager) == 0;
}

```
