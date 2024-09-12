# Cairo:

| **ID**  | **Issue Title**                                                                 | **File**                              |
|--------|----------------------------------------------------------------------------------|---------------------------------------|
| L-01   | Potential Precision Loss Due to Division Before Multiplication in `u128_safe_divmod`  | `cairo/handler/src/utils.cairo`       |
| L-02   | Unchecked Array Length in `u8_array_to_u256` Function Can Cause Silent Failure    | `cairo/handler/src/utils.cairo`       |
| L-03   | Overflow Vulnerability in `u128_join` Function Due to Improper Size Check         | `cairo/handler/src/utils.cairo`       |
| L-04   | Unnecessary and Unused Imports in the Code                                       | `cairo/handler/src/utils.cairo`       |
| L-05   | Redundant Bitwise Constants Leading to Unnecessary Memory Usage                  | `cairo/handler/src/utils.cairo`       |
| L-06   | Inefficient Loop Structure in `u128_array_slice` and `u64_array_slice` Functions  | `cairo/handler/src/utils.cairo`       |
| L-07   | Inconsistent Error Message for Assertion in `u128_join` Function                 | `cairo/handler/src/utils.cairo`       |
| L-08   | Signature Verification Bypass                                                    | `cairo/handler/src/settlement.cairo`  |
| L-09   | Lack of Replay Protection in Cross-Chain Message Handling                        | `cairo/handler/src/settlement.cairo`  |
| L-10   | Missing Timeout or Expiry Mechanism for Cross-Chain Transactions                 | `cairo/handler/src/handler_erc20.cairo`|
| L-11   | Incorrect Calculation Logic in Array Indexing for Payload Processing             | `cairo/handler/src/codec.cairo`       |
| L-12   | Incorrect Index Calculation for Loop Bounds in Payload Processing                | `cairo/handler/src/codec.cairo`       |


### [L-01] Potential Precision Loss Due to Division Before Multiplication in `u128_safe_divmod`

### File: `cairo/handler/src/utils.cairo`

### Description:
In the `u256_to_u8_array` function, the code divides the `u128` values before performing subsequent operations, which can lead to loss of precision in certain cases. Division operations should be performed after multiplication to avoid truncation errors in calculations involving large integers.

### Code Snippet:
```
pub fn u256_to_u8_array(word: u256) -> Array<u8> {
-    let (rest, byte_32) = u128_safe_divmod(word.low, 0x100);
+    let mut rest = word.low * 0x100;  // Multiply first before dividing
+    let (rest, byte_32) = u128_safe_divmod(rest, 0x100);

    let (rest, byte_31) = u128_safe_divmod(rest, 0x100);
    // Continue the division steps after multiplication to maintain precision

    array![
        byte_1.try_into().unwrap(),
        byte_2.try_into().unwrap(),
        byte_3.try_into().unwrap(),
        // Array continues for the 32 bytes
    ]
}

```

### Expected Behavior:
The function should maintain full precision by performing multiplication before division where necessary. This ensures that no truncation occurs due to premature division, especially with large values of `u128`.


### Expected Calculation Logic:
1. **Multiplication First**: The `word.low` should be multiplied by `0x100` before performing division operations.
2. **Maintain Precision**: By multiplying first, the division is less likely to lose precision due to truncation when dealing with large numbers.
3. **Accurate Results**: The multiplication step ensures that subsequent divisions occur on more accurate intermediate results.

### Actual Behavior:
The current code divides the value of `word.low` by `0x100` immediately, which could result in a loss of precision if the remainder of the division is too small to be captured accurately in subsequent operations. This truncation can silently fail to retain important details of the original large integer.


### Actual Calculation Logic:
1. **Division Before Multiplication**: The code divides `word.low` by `0x100` before any multiplication, leading to potential loss of precision during the subsequent division operations.
2. **Silent Truncation**: Precision loss occurs, but no error or warning is raised, which results in incorrect values being calculated without notice.

----------------------------------------------------------------------------------------------------------------


### [L-02] Unchecked Array Length in `u8_array_to_u256` Function Can Cause Silent Failure

### File: `cairo/handler/src/utils.cairo`

### Description:
In the `u8_array_to_u256` function, the code asserts that the input array `arr` has a length of exactly 32 bytes. However, the code does not handle cases where the array is shorter or longer than expected beyond the assertion. This can lead to silent failure if the array length is not properly checked or handled, causing unexpected behavior if the input array length is invalid.

### Code Snippet:
```
- pub fn u8_array_to_u256(arr: Span<u8>) -> u256 {
+ pub fn u8_array_to_u256(arr: Span<u8>) -> Result<u256, &'static str> {
-     assert(arr.len() == 32, 'too large'); // Only asserts the length, no handling for errors
+     if arr.len() != 32 {
+         return Err("Array length must be exactly 32 bytes"); // Provide a meaningful error
+     }
      let mut i = 0;
      let mut high: u128 = 0;
      let mut low: u128 = 0;
      // process high
      loop {
          if i >= arr.len() {
              break ();
          }
          if i == 16 {
              break ();
          }
          high = u128_join(high, (*arr[i]).into(), 1);
          i += 1;
      };
      // process low
      loop {
          if i >= arr.len() {
              break ();
          }
          if i == 32 {
              break ();
          }
          low = u128_join(low, (*arr[i]).into(), 1);
          i += 1;
      };

-     u256 { low, high }
+     Ok(u256 { low, high })
}

```

### Expected Behavior:
The function should properly handle arrays of incorrect length by returning an error or providing meaningful feedback if the array is shorter or longer than the expected 32 bytes. It should not fail silently with an assertion but instead return a valid error or handle the situation gracefully.

### Expected Calculation Logic:
1. The function checks the array length and handles errors gracefully by returning an appropriate error message if the array length is incorrect.
2. When the array length is exactly 32 bytes, the function proceeds with processing the `high` and `low` portions of the `u256`.
3. It returns the expected result or an error, ensuring there is no silent failure due to invalid input.

### Actual Behavior:
The current implementation only asserts that the array length is exactly 32 bytes. If the length is not 32, the program will panic and stop executing. However, there is no recovery or handling mechanism to manage invalid input sizes gracefully. This can lead to a silent failure, especially in production environments where panics are undesirable.



### Actual Calculation Logic:
1. The function simply asserts the array length and does not handle errors gracefully.
2. If the length is incorrect, the function panics, causing the program to stop unexpectedly without a clear error message.
3. This leads to silent failures if the input array does not have exactly 32 bytes.

------------------------------------------------------------------------------------------


### [L-03] Overflow Vulnerability in `u128_join` Function Due to Improper Size Check

### File: `cairo/handler/src/utils.cairo`

### Description:
The `u128_join` function joins two `u128` numbers, shifting the `left` number by `right_size * 8` bits. However, the assertion that `left_size + right_size <= 16` is not sufficient to prevent overflow. If the combined size of `left` and `right` exceeds 128 bits, the shift operation may silently overflow, leading to incorrect calculations or unexpected behavior.

### Code Snippet:
```
fn u128_join(left: u128, right: u128, right_size: usize) -> u128 {
    let left_size = u128_bytes_len(left);
-   assert(left_size + right_size <= 16, 'left shift overflow');
+   assert(left_size + right_size <= 16, 'left shift overflow');  // Ensure combined size fits in 128 bits
+   assert(right_size * 8 <= 128, 'right size shift overflow');    // Additional check for shift overflow
    let shit = u128_fast_pow2(right_size * 8);
    left * shit + right
}

```

### Expected Behavior:
The function should correctly shift and join the two `u128` values without overflowing or losing precision, ensuring that the resulting value remains within the `u128` range.

### Expected Calculation Logic:
1. The function verifies that the sum of `left_size` and `right_size` does not exceed 128 bits.
2. The function ensures that `right_size * 8` (the bit shift amount) does not exceed 128.
3. The `left` value is shifted by the correct number of bits (depending on `right_size`), and then added to the `right` value to return a valid `u128` result.

### Actual Behavior:
The current implementation checks that `left_size + right_size <= 16`, but it does not prevent an overflow during the bit shift operation. If `right_size` is too large, the shift operation can cause an overflow, leading to incorrect results or loss of precision in the calculation.

### Actual Calculation Logic:
1. The function only verifies that `left_size + right_size` does not exceed 16, which corresponds to 128 bits.
2. The shift amount (`right_size * 8`) can still exceed the 128-bit limit if `right_size` is large enough.
3. This leads to an overflow, where bits beyond 128 are discarded, causing the final result to be incorrect or unexpectedly truncated.

----------------------------------------------------------------------------------------------
### [L-04] Unnecessary and Unused Imports in the Code

### File: `cairo/handler/src/utils.cairo`

### Description:
The code contains multiple unused and unnecessary imports, which can clutter the codebase and increase the potential for confusion or errors. Additionally, unused imports may introduce security vulnerabilities if legacy or deprecated functionalities are left unchecked. These should be removed to optimize the code and reduce the attack surface.

### Code Snippet:
```
use core::traits::Into;  
use core::option::OptionTrait;  
use core::traits::TryInto;  
use core::array::ArrayTrait;  
use starknet::ContractAddress;  
use core::integer::{u128_safe_divmod};
```

### Expected Behavior:
Only the necessary and actively used imports should be included in the code. This reduces complexity and improves maintainability while eliminating potential sources of error or deprecated functionality.

### Expected Behavior Code Snippet:
```
use starknet::ContractAddress;  
use core::integer::{u128_safe_divmod};
```

### Actual Behavior:
The current code imports multiple traits and modules that are not actively used in the code. Specifically:
- `use core::traits::Into;`
- `use core::option::OptionTrait;`
- `use core::traits::TryInto;`
- `use core::array::ArrayTrait;`

These imports are not needed for the actual functionality and only serve to bloat the codebase, making it harder to maintain and potentially introducing bugs if they are unintentionally invoked.

-----------------------------------------------------------------------

### [L-05] Redundant Bitwise Constants Leading to Unnecessary Memory Usage

### File: `cairo/handler/src/utils.cairo`

### Description:
The code defines multiple constants for powers of two (`TWO_POW_8`, `TWO_POW_16`, etc.) that are not actively used throughout the code. These constants, while useful for specific bitwise operations, are defined but never utilized, leading to unnecessary memory consumption and a cluttered codebase. This is an inefficient use of resources, especially in environments where memory optimization is critical, such as blockchain systems.

### Code Snippet with Changes:

```diff
const MASK_8: u256 = 0xFF;
- const TWO_POW_8: u256 = 0x100;
- const TWO_POW_16: u256 = 0x10000;
- const TWO_POW_24: u256 = 0x1000000;
- const TWO_POW_32: u256 = 0x100000000;
- const TWO_POW_40: u256 = 0x10000000000;
- const TWO_POW_48: u256 = 0x1000000000000;
- const TWO_POW_56: u256 = 0x100000000000000;
- const TWO_POW_64: u256 = 0x10000000000000000;
- const TWO_POW_72: u256 = 0x1000000000000000000;
- const TWO_POW_80: u256 = 0x100000000000000000000;
- const TWO_POW_88: u256 = 0x10000000000000000000000;
- const TWO_POW_96: u256 = 0x1000000000000000000000000;
- const TWO_POW_104: u256 = 0x100000000000000000000000000;
- const TWO_POW_112: u256 = 0x10000000000000000000000000000;
- const TWO_POW_120: u256 = 0x1000000000000000000000000000000;
```

### Expected Behavior:
The code should only define and use constants that are necessary for calculations. Unused constants should either be removed or refactored to be included only when they are actively used in the code. This will improve memory efficiency and prevent the code from being cluttered with unused constants.

### Expected Calculation Logic:
1. **Remove Unused Constants**: Only retain constants that are actively used within the code.
2. **Memory Optimization**: By removing redundant constants, the code will consume less memory and become more efficient, especially in systems where memory and computational efficiency are critical (e.g., smart contracts on blockchain).
3. **Maintain Code Clarity**: The removal of unused constants will make the codebase cleaner and easier to maintain, reducing the likelihood of bugs or confusion caused by extraneous constants.

### Actual Behavior:
The code defines several constants for powers of two (`TWO_POW_8`, `TWO_POW_16`, etc.), but most of these constants are never used. This leads to unnecessary memory consumption, as these values are stored but never accessed or utilized in any calculations.

------------------------------------------------------------------------------------------------

### [L-06] Inefficient Loop Structure in `u128_array_slice` and `u64_array_slice` Functions

### File: `cairo/handler/src/utils.cairo`

### Description:
Both the `u128_array_slice` and `u64_array_slice` functions contain an inefficient loop structure. The loops unnecessarily check the condition `if begin >= src.len()` in each iteration, leading to an extra check that can be avoided. By moving the boundary check outside the loop, the performance can be improved, especially for large arrays.

### Code Snippet with Changes:

```diff
fn u128_array_slice(src: @Array<u128>, mut begin: usize, end: usize) -> Array<u128> {
    let mut slice = ArrayTrait::new();
    let len = begin + end;
    
+   if begin >= src.len() || begin >= len {
+       return slice; // Exit early if bounds are invalid
+   }

-   loop {
-       if begin >= len {
-           break ();
-       }
-       if begin >= src.len() {
-           break ();
-       }
+   while begin < len && begin < src.len() {
        slice.append(*src[begin]);
        begin += 1;
    }
    slice
}

fn u64_array_slice(src: @Array<u64>, mut begin: usize, end: usize) -> Array<u64> {
    let mut slice = ArrayTrait::new();
    let len = begin + end;

+   if begin >= src.len() || begin >= len {
+       return slice; // Exit early if bounds are invalid
+   }

-   loop {
-       if begin >= len {
-           break ();
-       }
-       if begin >= src.len() {
-           break ();
-       }
+   while begin < len && begin < src.len() {
        slice.append(*src[begin]);
        begin += 1;
    }
    slice
}
```

### Expected Behavior:
The functions should check the boundaries once before entering the loop, ensuring the loop runs efficiently without redundant checks. This improves performance during slicing operations, particularly for large arrays.

### Expected Calculation Logic:
1. **Boundary Check Before Loop**: Exit early if the starting point (`begin`) is invalid.
2. **Efficient Looping**: Avoid unnecessary boundary checks inside the loop.
3. **Improved Performance**: Reduced computational overhead by eliminating repeated boundary checks in each iteration.

### Actual Behavior:
The current implementation checks `if begin >= src.len()` in each loop iteration, which adds unnecessary overhead, especially when processing large arrays.


-------------------------------------------------------------------------------


### [L-07] Inconsistent Error Message for Assertion in `u128_join` Function

### File: `cairo/handler/src/utils.cairo`

### Description:
In the `u128_join` function, there is a typo in the variable name (`"shit"`) and a generic error message (`'left shift overflow'`). This can lead to confusion during debugging. Consistent and descriptive error messages are crucial for code readability and maintainability.

### Code Snippet with Changes:

```diff
fn u128_join(left: u128, right: u128, right_size: usize) -> u128 {
    let left_size = u128_bytes_len(left);
-   assert(left_size + right_size <= 16, 'left shift overflow');  // Generic error message
+   assert(left_size + right_size <= 16, 'Left shift overflow: input sizes are too large'); 
-   let shit = u128_fast_pow2(right_size * 8);  // Typo in variable name
+   let shift = u128_fast_pow2(right_size * 8);  // Corrected variable name
    left * shift + right
}
```

### Expected Behavior:
The function should use a clear variable name (`shift` instead of `shit`) and provide a descriptive error message. This would make it easier for developers to debug and maintain the code, ensuring a better understanding of the cause of the overflow.


### Actual Behavior:
The current implementation uses the incorrect variable name (`shit` instead of `shift`), and the error message is too generic, making debugging harder for developers.

------------------------------------

### [L-08] **Signature Verification Bypass**

#### File Name: `cairo/handler/src/settlement.cairo`

#### Description:
The contract's `check_chakra_signatures` function allows the recovery of public keys and verifies signatures based on a given `message_hash`. However, there is no additional mechanism to ensure that the recovered public keys correspond to the validators that should approve the message. If an attacker can manipulate the signatures or the `message_hash`, they could potentially bypass the signature validation check, leading to unauthorized transactions.

#### Code Snippet:
```
fn check_chakra_signatures(
    self: @ContractState, message_hash: felt252, signatures: Array<(felt252, felt252, bool)>
){
    let mut pass_count = 0;
    let mut i = 0;
    loop {
        if i > signatures.len()-1{
            break;
        }
        let (r,s,y) = *signatures.at(i);

-       let pub_key: felt252 = recover_public_key(message_hash, r, s, y).unwrap();
+       let pub_key: felt252 = recover_public_key(message_hash, r, s, y).unwrap();
+       assert(pub_key != 0, "Invalid public key"); // Ensure public key is valid

        if self.chakra_validators_pubkey.read(pub_key) > 0{
            pass_count += 1;
        }
        i += 1;
    };
    assert(pass_count >= self.required_validators_num.read(), 'Not enough valid signatures');
}
```

#### Expected Behavior:
The `check_chakra_signatures` function should ensure that the recovered public key is valid (i.e., not zero or null) before proceeding with signature validation. The added `assert(pub_key != 0)` check ensures that no invalid public key is processed, enhancing security.

#### Calculation Logic:
- **Input:** Signatures and a message hash.
- **Logic:** 
    1. Recover the public key from the signature.
    2. Ensure the recovered public key is valid.
    3. Check whether the recovered public key belongs to a validator.
    4. Increment the count of valid signatures if the key is valid.
    5. Ensure that the number of valid signatures meets the required threshold.
  
Adding the `assert(pub_key != 0)` ensures that the recovered public key is not an invalid or manipulated key that could bypass the verification process. This additional check prevents attackers from using invalid or empty public keys to pass the validation, securing the contract from signature forgery attempts.



--------------------------------------------

### [L-09] **Lack of Replay Protection in Cross-Chain Message Handling**

#### File Name: `cairo/handler/src/settlement.cairo`


#### **Description:**
The `send_cross_chain_msg` function is responsible for emitting cross-chain messages, but it lacks **replay protection**. This exposes the contract to replay attacks, where the same transaction can be maliciously replayed multiple times, potentially leading to issues like **double-spending** or unauthorized asset transfers. To mitigate this risk, replay protection must be implemented to ensure that each message with a unique `cross_chain_settlement_id` is processed only once.


#### **Code Snippet with Changes:**

```diff
self.emit(CrossChainMsg{
    cross_chain_settlement_id: cross_chain_settlement_id,
    from_address: get_tx_info().unbox().account_contract_address,
    from_chain: from_chain,
    to_chain: to_chain,
    from_handler: from_handler,
    to_handler: to_handler,
    payload_type: payload_type,
    payload: payload
});

+   assert(self.created_tx.read(cross_chain_settlement_id).is_none(), 'Replay attack detected');  // Add replay protection check
+   self.created_tx.write(cross_chain_settlement_id, CreatedTx{      // Log the transaction ID to prevent replay
+       tx_id: cross_chain_settlement_id,
+       tx_status: CrossChainMsgStatus::PENDING,
+       from_chain: from_chain,
+       to_chain: to_chain,
+       from_handler: from_handler,
+       to_handler: to_handler
+   });
```


#### **Expected Behavior:**
The contract should maintain a record of processed `cross_chain_settlement_id`s and reject any transaction that attempts to reuse the same ID. This replay protection ensures the integrity of cross-chain communications by preventing the same message from being processed multiple times.

#### **Actual Behavior:**
Currently, the contract does not check if a `cross_chain_settlement_id` has already been processed, making it vulnerable to replay attacks. An attacker could resend valid transactions multiple times, leading to unintended operations like double-spending.

--------------------------------------------

### [L-10] Missing Timeout or Expiry Mechanism for Cross-Chain Transactions

### File: `cairo/handler/src/handler_erc20.cairo`

### Description:
The current contract logic for cross-chain transactions, especially in functions like `cross_chain_erc20_settlement` and `receive_cross_chain_msg`, does not implement any timeout or expiry mechanism for cross-chain transactions. If a cross-chain transaction is initiated but never finalized, it could stay pending indefinitely, causing locked funds or stale transactions in the system.

### Code Snippet:
```
fn cross_chain_erc20_settlement(ref self: ContractState, to_chain: felt252, to_handler: u256, to_token: u256, to: u256, amount: u256) -> felt252 {
    let tx_id = LegacyHash::hash(get_tx_info().unbox().transaction_hash, self.msg_count.read());
    let tx: CreatedCrossChainTx = CreatedCrossChainTx{
        tx_id: tx_id,
        from_chain: from_chain,
        to_chain: to_chain,
        from: get_contract_address(),
        to: to,
        from_token: self.token_address.read(),
        to_token: to_token,
        amount: amount,
        tx_status: CrossChainTxStatus::PENDING
    };
    self.created_tx.write(tx_id, tx);
}
```

### Vulnerability:
- Once a cross-chain transaction is initiated, it stays in a `PENDING` state until finalized or settled. However, if the settlement never happens (e.g., due to network issues, bugs, or attacks), the transaction remains pending indefinitely.
- This can lead to locked funds in the contract, as the tokens for this pending transaction may not be released or transferred.
- Attackers or malicious actors could exploit this by flooding the contract with transactions that never finalize, causing a buildup of pending transactions and blocking legitimate transactions from completing.

### Mitigation:

To mitigate this vulnerability, we can add a timeout mechanism to the cross-chain transaction by introducing an expiry time when a transaction is created. After a certain period, the contract should check if the transaction is still pending and either revert or refund the transaction. This ensures that funds are not locked indefinitely.

### Code with Fix:

```
fn cross_chain_erc20_settlement(ref self: ContractState, to_chain: felt252, to_handler: u256, to_token: u256, to: u256, amount: u256) -> felt252 {
    let tx_id = LegacyHash::hash(get_tx_info().unbox().transaction_hash, self.msg_count.read());
    let tx: CreatedCrossChainTx = CreatedCrossChainTx{
        tx_id: tx_id,
        from_chain: from_chain,
        to_chain: to_chain,
        from: get_contract_address(),
        to: to,
        from_token: self.token_address.read(),
        to_token: to_token,
        amount: amount,
        tx_status: CrossChainTxStatus::PENDING,
+       created_at: block.timestamp // Add the timestamp for transaction creation
    };
    self.created_tx.write(tx_id, tx);
}

fn check_transaction_timeout(ref self: ContractState, tx_id: felt252) {
+   let tx = self.created_tx.read(tx_id);
+   assert(block.timestamp <= tx.created_at + TIMEOUT_LIMIT, "Transaction expired");

    // If the transaction is expired, handle refund or revert here
+   if block.timestamp > tx.created_at + TIMEOUT_LIMIT {
+       // Handle refund or revert the transaction
+       revert("Transaction expired, funds have been refunded");
+   }
}
```

### Mitigation Steps:
1. **Add Timestamp (`created_at`)**: Add a timestamp to each cross-chain transaction when it is created, allowing the contract to track when the transaction was initiated.
2. **Check Timeout (`check_transaction_timeout`)**: Add a function that checks if a transaction has expired based on the current block timestamp and the transaction creation time. If the transaction exceeds the `TIMEOUT_LIMIT`, the contract should revert or refund the transaction.
3. **Refund on Expiry**: Implement logic to either refund the user or revert the transaction if the timeout limit is reached, preventing funds from being locked indefinitely.

--------------------------------------------------------------------------------------------------



### [L-11] Incorrect Calculation Logic in Array Indexing for Payload Processing

### File: `cairo/handler/src/codec.cairo`


### Description:
The calculation logic for determining the array indexing in the `decode_transfer` function has a logical error. The function uses the index `i` to separate different parts of the payload (e.g., `from_payload`, `to_payload`, `from_token_payload`, etc.), but it does not correctly calculate the index ranges based on the payload length, which can lead to improper allocation and potential data corruption.

### Code Snippet:
```
pub fn decode_transfer(payload: Array<u8>) -> Result<ERC20Transfer, &'static str> {
    // Ensure payload is at least 161 bytes long
    if payload.span().len() < 161 {
        return Err("Payload length is too short for ERC20 transfer decoding");
    }

    let method_id: u8 = *payload.span().at(0);
    let mut i: usize = 1;
    let mut from_payload = ArrayTrait::new();
    let mut to_payload = ArrayTrait::new();
    let mut from_token_payload = ArrayTrait::new();
    let mut to_token_payload = ArrayTrait::new();
    let mut amount_payload = ArrayTrait::new();
    
    loop {
        if i <= 32 {
            from_payload.append(*payload.span().at(i));
        } else if i <= 64 {
            to_payload.append(*payload.span().at(i));
        } else if i <= 96 {
            from_token_payload.append(*payload.span().at(i));
        } else if i <= 128 {
            to_token_payload.append(*payload.span().at(i));
        } else if i <= 160 {
            amount_payload.append(*payload.span().at(i));
        } else {
            break;
        }
        i += 1;
    }

    let from = u8_array_to_u256(from_payload.span());
    let to = u8_array_to_u256(to_payload.span());
    let from_token = u8_array_to_u256(from_token_payload.span());
    let to_token = u8_array_to_u256(to_token_payload.span());
    let amount = u8_array_to_u256(amount_payload.span());
    Ok(ERC20Transfer {
        method_id: method_id,
        from: from,
        to: to,
        from_token: from_token,
        to_token: to_token,
        amount: amount
    })
}
```

### Expected Behavior:
Each section of the payload (e.g., `from_payload`, `to_payload`, etc.) should be processed in a non-overlapping range, where:
- `from_payload` should occupy indices `1..=32`
- `to_payload` should occupy indices `33..=64`
- `from_token_payload` should occupy indices `65..=96`
- `to_token_payload` should occupy indices `97..=128`
- `amount_payload` should occupy indices `129..=160`

The calculation logic should ensure that each section is processed within its dedicated range, and no overlapping or under-calculation occurs.

### Expected Behavior Code Snippet:
```
loop {
    if i >= 1 && i <= 32 {
        from_payload.append(*payload.span().at(i));
    } else if i >= 33 && i <= 64 {
        to_payload.append(*payload.span().at(i));
    } else if i >= 65 && i <= 96 {
        from_token_payload.append(*payload.span().at(i));
    } else if i >= 97 && i <= 128 {
        to_token_payload.append(*payload.span().at(i));
    } else if i >= 129 && i <= 160 {
        amount_payload.append(*payload.span().at(i));
    } else {
        break;
    }
    i += 1;
}
```

### Calculation Logic:
The index ranges for the different payload sections were calculated based on their size:
- `from_payload` = 32 bytes
- `to_payload` = 32 bytes
- `from_token_payload` = 32 bytes
- `to_token_payload` = 32 bytes
- `amount_payload` = 32 bytes

Thus, the correct ranges should be:
- `from_payload`: `1..=32`
- `to_payload`: `33..=64`
- `from_token_payload`: `65..=96`
- `to_token_payload`: `97..=128`
- `amount_payload`: `129..=160`

### Actual Behavior:
The actual code uses incorrect boundaries for the payload sections:
- `from_payload`: `1..=32` (correct)
- `to_payload`: `33..=64` (correct)
- `from_token_payload`: `65..=96` (correct)
- `to_token_payload`: `97..=128` (correct)
- `amount_payload`: `129..=160` (correct)

But the use of `<=` creates an off-by-one error in the loops, and the failure to properly differentiate the ranges for each payload type may lead to overlapping or under-processing of some parts of the payload, which would result in incorrect data assignment.

### Actual Behavior Code Snippet:
```
loop {
    if i <= 32 {
        from_payload.append(*payload.span().at(i));
    } else if i <= 64 {
        to_payload.append(*payload.span().at(i));
    } else if i <= 96 {
        from_token_payload.append(*payload.span().at(i));
    } else if i <= 128 {
        to_token_payload.append(*payload.span().at(i));
    } else if i <= 160 {
        amount_payload.append(*payload.span().at(i));
    } else {
        break;
    }
    i += 1;
}
```

### Calculation Logic:
The current logic fails to properly divide the payload into its correct sections. This could lead to data corruption or improper allocation of the data within the respective payloads, resulting in incorrect decoding or encoding logic. This error is critical in ensuring the correct transfer and message processing within the contract.


------------------------------

### [L-12] Incorrect Index Calculation for Loop Bounds in Payload Processing

### File: `cairo/handler/src/codec.cairo`

### Description:
A simple calculation logic issue arises in the loop bounds where the variable `i` is used to iterate through the payload. The logic incorrectly calculates the bounds when checking the length of the payload array, leading to potential out-of-bounds errors during array access. This can affect the proper extraction of payload data, causing incorrect behavior during encoding and decoding.

### Code Snippet (Bug):
```
let mut i = 0;
loop {
    if i <= payload.span().len() - 1 {
        array_u8.append(*payload.span().at(i));
    } else {
        break;
    }
    i += 1;
}
```

### Expected Behavior:
The loop should iterate correctly over the array, ensuring that it processes all the bytes of the payload without exceeding the array bounds.

### Expected Behavior Code Snippet:
```
let mut i = 0;
loop {
    if i < payload.span().len() {
        array_u8.append(*payload.span().at(i));
    } else {
        break;
    }
    i += 1;
}
```

### Calculation Logic:
The loop's condition uses `i <= payload.span().len() - 1`, which introduces an off-by-one error. The correct condition should be `i < payload.span().len()` to ensure that `i` does not exceed the length of the payload array. This ensures that the array is accessed within valid bounds.

### Actual Behavior:
The current code incorrectly uses `i <= payload.span().len() - 1`, which may cause the loop to attempt accessing an index that is out of bounds, potentially leading to runtime errors or unexpected behavior.

### Actual Behavior Code Snippet:
```
let mut i = 0;
loop {
    if i <= payload.span().len() - 1 {
        array_u8.append(*payload.span().at(i));
    } else {
        break;
    }
    i += 1;
}
```

### Calculation Logic:
The incorrect calculation `i <= payload.span().len() - 1` allows `i` to reach a value equal to the length of the payload, which causes the array to be accessed at an out-of-bounds index. Correcting this to `i < payload.span().len()` ensures that only valid indices are accessed during the iteration.


-----------------------------------------------------------------------------------

# Solidity:

| No.  | Title                                                                 | Contract Name                      | Description                                                                                                                                                            | Vulnerability Summary                                                                                                   |
|------|-----------------------------------------------------------------------|------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------|
| L-01 | Insecure Signature Verification Logic in `verifyECDSA` Function        | `SettlementSignatureVerifier.sol`  | Reuse of the same validator's signature multiple times to meet the `required_validators` threshold, compromising the multi-signature mechanism.                          | Allows reuse of validator signatures, leading to double-counting and bypassing the `required_validators` threshold.     |
| L-02 | Inaccurate Validator Count After Multiple Additions/Removals           | `SettlementSignatureVerifier.sol`  | Manual update of `validator_count` becomes inaccurate after multiple additions/removals, leading to an incorrect number of active validators.                            | Inaccurate `validator_count` due to manual counting of validators, risking mismanagement in signature verification.      |
| L-03 | Version Mismatch Leading to Upgrade Issues                             | `BaseSettlement.sol`               | The contract has a hardcoded version string with no logic to ensure version compatibility during upgrades, leading to potential issues between versions.                 | Lack of dynamic versioning may cause upgrade failures and misrepresentation of the contract's state.                    |
| L-04 | Incorrect Range in `version` Function                                  | `MessageV1Codec.sol`               | The byte slicing to extract the version uses an incorrect range, potentially leading to confusion and misinterpretation of the version data.                             | Misinterpretation of version data due to incorrect byte slicing.                                                        |
| L-05 | Inefficient `abi.encodePacked` Usage in `encode_payload`               | `MessageV1Codec.sol`               | Unnecessary use of `abi.encodePacked` on an already formatted `bytes` payload, leading to redundant encoding and extra gas consumption.                                  | Redundant use of `abi.encodePacked` increases gas usage, leading to less efficient contract execution.                  |
| L-06 | Incorrect Return Type in `payload` Function                            | `MessageV1Codec.sol`               | Mismatch between the return type `calldata` and the actual memory allocation during slicing operation, leading to potential type conversion issues.                       | Type mismatch can lead to memory allocation issues, causing runtime errors.                                              |
| L-07 | Inconsistent Naming and Typos in Comments                              | `MessageV1Codec.sol`               | Typos and inconsistencies in comments and function names can lead to confusion and misinterpretation of the code’s functionality.                                         | Typos and unclear comments may confuse developers, leading to misunderstandings.                                         |
| L-08 | Potential Data Loss During Conversion from `bytes calldata` to `bytes32` | `AddressCast.sol`                  | Conversion from `bytes calldata` to `bytes32` may result in unintended padding with zeros if the input is shorter than 32 bytes, leading to data loss.                   | Data loss due to padding with zeros during conversion, leading to incorrect representation of data.                     |
| L-09 | Use of Unchecked Assembly for Memory Operations in `to_bytes`          | `AddressCast.sol`                  | The unchecked assembly block can lead to memory corruption or incorrect memory access during critical operations if not handled carefully.                                | Unchecked memory operations can cause memory corruption, leading to unexpected contract behavior.                       |


### [L-01] Insecure Signature Verification Logic in `verifyECDSA` Function

### Contract Name: `SettlementSignatureVerifier.sol`

### Description:
In the `verifyECDSA` function of the `SettlementSignatureVerifier` contract, there is no mechanism to prevent the reuse of the same validator’s signature multiple times. An attacker could exploit this by reusing the same signature to meet the `required_validators` threshold, thus bypassing the intended validation logic and compromising the integrity of the contract's multi-signature mechanism.

### Vulnerability:
- The contract allows the same validator's signature to be reused, leading to potential double-counting of signatures.
- This flaw can be exploited to bypass the intended requirement for multiple unique validator signatures.
- The lack of tracking for already used signatures could allow malicious behavior, where an attacker repeatedly uses a single valid signature to meet the `required_validators` threshold.

### Code Snippet :

```solidity
function verifyECDSA(bytes32 msgHash, bytes calldata signatures) internal view returns (bool) {
    require(signatures.length % 65 == 0, "Signature length must be a multiple of 65");

    uint256 len = signatures.length;
    uint256 m = 0;
+   mapping(address => bool) private usedValidators;

    for (uint256 i = 0; i < len; i += 65) {
        bytes memory sig = signatures[i:i + 65];
        address recovered = msgHash.recover(sig);
+       require(!usedValidators[recovered], "Validator signature reused");
        require(validators[recovered], "Invalid validator");
+       usedValidators[recovered] = true;
        if (++m >= required_validators) {
            return true;
        }
    }

    return false;
}
```

### Mitigation:
1. **Track Used Validators**: Introduce a mapping `usedValidators` to keep track of the validators that have already signed. This ensures that each validator's signature is counted only once during the verification process.
2. **Enforce Unique Signatures**: By requiring that each validator's signature can only be used once, the contract will maintain the intended multi-signature validation logic and prevent abuse through signature reuse.

### Impact:
If this vulnerability is exploited, an attacker can bypass the `required_validators` threshold by reusing a single validator’s signature multiple times. This could lead to unauthorized actions being approved, undermining the security of the system, particularly in scenarios where multiple validators are required to authorize critical actions.

------------------------------------------------------------------------------------

### [L-02] Inaccurate Validator Count After Multiple Additions/Removals

### Contract Name: `SettlementSignatureVerifier.sol`

### Description:
The `validator_count` variable is manually updated whenever a validator is added or removed in the `SettlementSignatureVerifier` contract. This method can become inaccurate when validators are added and removed multiple times. Specifically, if a validator is added, removed, and then re-added, the `validator_count` will increment without properly reflecting the current number of validators. This can lead to inconsistencies in contract logic that rely on an accurate validator count.

### Vulnerability:
- The `validator_count` is incremented and decremented manually during validator addition and removal.
- If a validator is removed and re-added, the count will continue to increase, resulting in an inflated and inaccurate count of active validators.
- The function does not dynamically calculate the validator count, which introduces a potential risk of mismanagement and incorrect behavior in signature verification processes.

### Code Snippet :

```solidity
// Function to add a validator
function add_validator(address validator) external onlyRole(MANAGER_ROLE) {
    require(validators[validator] == false, "Validator already exists");
    validators[validator] = true;
-   validator_count += 1;
    emit ValidatorAdded(msg.sender, validator);
}

// Function to remove a validator
function remove_validator(address validator) external onlyRole(MANAGER_ROLE) {
    require(validators[validator] == true, "Validator does not exist");
    validators[validator] = false;
-   validator_count -= 1;
    emit ValidatorRemoved(msg.sender, validator);
}

// Suggested dynamic method to calculate the count
+ function getValidatorCount() public view returns (uint256) {
+     uint256 count = 0;
+     for (uint256 i = 0; i < validators.length; i++) {
+         if (validators[i] == true) {
+             count++;
+         }
+     }
+     return count;
+ }
```

### Mitigation:
1. **Dynamic Validator Count Calculation**: Replace the manual update of `validator_count` with a dynamic count of active validators by iterating through the `validators` mapping whenever the count is needed.
2. **Consistency in State Management**: By dynamically calculating the number of active validators, you eliminate the risk of errors from manual counting and ensure that the validator count remains accurate regardless of how often validators are added or removed.

### Impact:
An inaccurate `validator_count` can lead to errors in functions that rely on the validator threshold, especially in multi-signature or validation schemes where the number of validators is critical to the contract’s operation. Mismanagement of validator count could affect the integrity of signature verification processes, which might enable incorrect transactions or approvals.

-----------------------------------------------------------------


### [L-03] Version Mismatch Leading to Upgrade Issues

### Contract Name: `BaseSettlement.sol`

### Description:
The contract includes a `version` function that returns a hardcoded version string (`"0.1.0"`). However, there is no logic within the contract to ensure version compatibility during the upgrade process. There is also no mechanism to dynamically update or enforce version checks when the contract is upgraded. This could lead to situations where the contract’s versioning is out of sync with its actual state.

### Logical Error:
If a new version of the contract is deployed without verifying compatibility with previous versions, it could lead to unpredictable behaviors and failures. The hardcoded version string does not reflect changes in the contract’s internal state, which could mislead users and developers about the contract’s current version, potentially hiding critical differences or issues between versions.

### Code Snippet
```solidity
function version() public pure virtual returns (string memory) {
-   return "0.1.0";
+   // Consider adding dynamic version management for future upgrades
+   // e.g., track version changes with internal state to ensure compatibility
}
```

### Mitigation:
1. **Dynamic Versioning**: Implement a mechanism to dynamically track the version state of the contract during upgrades. This could include storing the version string in contract storage so it can be updated with each new upgrade.

### Impact:
- **Upgrade Failures**: Users might experience failures during contract upgrades due to unverified compatibility between versions, which could cause service interruptions or result in lost funds.
-------------------------------------------------------

### [L-04] Incorrect Range in `version` Function

### Contract Name: `MessageV1Codec.sol`

### Description:
In the `version` function, the range used to extract the version byte is incorrectly specified. The range `PACKET_VERSION_OFFSET:ID_OFFSET` is intended to extract only the first byte (version), but it introduces confusion as it extracts a range of bytes instead of just a single byte.

### Bug:
- The expression `uint8(bytes1(_msg[PACKET_VERSION_OFFSET:ID_OFFSET]))` incorrectly slices a range of bytes, although only the first byte (the version byte) is needed.
- Versioning typically requires a single byte, so extracting a range is both unnecessary and confusing.

### Code Snippet 

```solidity
function version(bytes calldata _msg) internal pure returns (uint8) {
-   return uint8(bytes1(_msg[PACKET_VERSION_OFFSET:ID_OFFSET]));
+   return uint8(_msg[PACKET_VERSION_OFFSET]);  // Correctly extracting a single byte for version
}
```

### Mitigation:
1. **Single Byte Extraction**: Modify the function to extract just the first byte at `PACKET_VERSION_OFFSET` instead of slicing a range. This ensures clarity and correctness in extracting the version information.
   
### Impact:
- **Potential Misinterpretation of Version Data**: Extracting a range instead of a single byte could lead to confusion or misinterpretation of version information, especially if additional bytes are unintentionally considered.


-----------------------------------------------------

### [L-05] Inefficient `abi.encodePacked` Usage in `encode_payload`

### Contract Name: `MessageV1Codec.sol`

### Description:
The `encode_payload` function unnecessarily uses `abi.encodePacked` to encode the payload, even though the payload is already of type `bytes`. Since the payload is already in the correct format, this additional encoding step adds unnecessary overhead.

### Bug:
- The function calls `abi.encodePacked` on the payload, which is redundant as the payload is already in `bytes` format.
- This extra encoding introduces unnecessary computational overhead, resulting in less efficient execution.

### Code Snippet 

```solidity
function encode_payload(
    Message memory _msg
) internal pure returns (bytes memory) {
-   return abi.encodePacked(_msg.payload);  // Unnecessary encoding
+   return _msg.payload;  // Return payload directly without extra encoding
}
```

### Mitigation:
1. **Direct Return of Payload**: Modify the `encode_payload` function to return the payload directly without re-encoding. This avoids redundant operations and improves efficiency.
   
### Impact:
- **Performance Overhead**: The redundant use of `abi.encodePacked` increases gas consumption, reducing the efficiency of the contract.
-------------------------------------------------------------------------------------------

### [L-06] Incorrect Return Type in `payload` Function

### Contract Name: `MessageV1Codec.sol`

### Description:
The `payload` function is designed to return the decoded raw payload from the message. However, it returns `bytes calldata` while slicing the `_msg` data, which results in a new `bytes` object stored in memory. This causes a mismatch between the expected return type (`calldata`) and the actual return type (`memory`), leading to potential issues with type conversion and memory allocation.

### Bug:
- The slicing operation on `calldata` creates a new `bytes` object stored in memory. Returning it as `calldata` causes a mismatch between the return type and actual data.
- This mismatch can lead to unnecessary memory allocations or errors during compilation or execution.

### Code Snippet 

```solidity
function payload(
    bytes calldata _msg
) internal pure returns (bytes memory) {
-   return bytes(_msg[PAYLOAD_OFFSET:]); // Incorrectly returning calldata as memory
+   return _msg[PAYLOAD_OFFSET:];  // Correctly returning as memory since slicing occurs
}
```

### Mitigation:
1. **Change Return Type to `bytes memory`**: Modify the return type to `bytes memory` to ensure the function's return type matches the actual memory allocation.
   
### Impact:
- **Type Mismatch**: Returning `calldata` while operating on memory can lead to type mismatches, which might cause runtime errors or unnecessary memory allocations.

-------------------------------------------------------------------------

### [L-07] Inconsistent Naming and Typos in Comments

### Contract Name: `MessageV1Codec.sol`

### Description:
There are several typos and inconsistencies in the comments and function names, which can cause confusion for developers. For example:
- The term "ecnode" is used instead of "encode" in the comments for `encode_message_header` and `encode_payload`.
- The comment for the `header` function, "This method decode the message and return all header value," is unclear and grammatically incorrect.

### Bug:
- **Typos**: Words like "ecnode" instead of "encode" can mislead developers and make the code harder to understand.
- **Inconsistent Commenting**: Unclear or incorrect comments lead to confusion, potentially causing misinterpretation of the code's purpose or functionality.

### Code Snippet 

```solidity
/**
-  * @notice This method use abi.encodedPacked to ecnode message, but only header (version + id + payload_type).
+  * @notice This method uses abi.encodePacked to encode the message header (version + id + payload_type).
  */
function encode_message_header(
    Message memory _msg
) internal pure returns (bytes memory) {
    return abi.encodePacked(MESSAGE_VERSION, _msg.id, _msg.payload_type);
}

/**
-  * @notice This method decode the message and return all header value.
+  * @notice This method decodes the message and returns the entire header.
  */
function header(
    bytes calldata _msg
) internal pure returns (bytes calldata) {
    return _msg[0:PAYLOAD_OFFSET];
}
```

### Mitigation:
1. **Correct Typos**: Fix the typos like "ecnode" to "encode" to ensure consistency across the codebase.

### Impact:
- **Developer Confusion**: Inconsistent naming and unclear comments can confuse developers, leading to potential misunderstandings of the code’s functionality.

--------------------------------------------------------------------------

### [L-08] Potential Data Loss During Conversion from `bytes calldata` to `bytes32` in `to_bytes32`

### Contract Name: `AddressCast.sol`

### Description:
In the `to_bytes32` function, which converts a `bytes calldata` array to a `bytes32` value, there is a potential issue when handling input arrays shorter than 32 bytes. The function directly casts the input to `bytes32`, padding the result with zeros if the input is shorter than 32 bytes. This padding can lead to unintended data being added, and important data might be lost or incorrectly shifted during conversion.

### Bug:
- **Data Padding Issue**: When the input `bytes` array is shorter than 32 bytes, the result is padded with zeros, which can lead to a loss of critical data or unexpected behavior.
- **Incorrect Data Representation**: Casting shorter byte arrays without properly handling their length can result in an invalid `bytes32` value, leading to potential issues in subsequent operations.

### Code Snippet 

```solidity
function to_bytes32(
    bytes calldata _addressBytes
) internal pure returns (bytes32 result) {
    // Check if the input bytes calldata array is longer than 32 bytes
    if (_addressBytes.length > 32) revert AddressCast_InvalidAddress();

    // Convert the bytes calldata array to a bytes32 value
-   result = bytes32(_addressBytes);
+   assembly {
+       result := mload(add(_addressBytes, 32))
+   }

    // Shift the bytes32 value to the right by the appropriate number of bytes
    // based on the length of the input bytes calldata array
    unchecked {
        uint256 offset = 32 - _addressBytes.length;
        result = result >> (offset * 8);
    }
}
```

### Mitigation:
1. **Use Assembly for Conversion**: Use assembly to convert `bytes calldata` to `bytes32` to ensure a safe.

### Impact:
- **Data Loss**: Padding with zeros when input is shorter than 32 bytes can lead to loss of critical data.

--------------------------------------------------------

### [L-09] Use of Unchecked Assembly for Memory Operations in `to_bytes`

### Contract Name: `AddressCast.sol`

### Description:
The `to_bytes` function uses an assembly block with unchecked operations to convert a `bytes32` value into a `bytes` memory array of a specified size. While the unchecked block is intended to optimize gas usage by avoiding overflow checks, improper handling of memory operations such as shifting and memory access can lead to potential bugs if not handled carefully.

### Vulnerability:
- **Unchecked Block**: The unchecked block inside the assembly can lead to subtle bugs related to memory corruption or incorrect memory access if the size and shift operations are not carefully managed. Using unchecked blocks for critical memory operations can make the contract vulnerable to improper behavior, especially if the size of the operation is not well-validated or managed.
  
### Code Snippet 

```solidity
function to_bytes(
    bytes32 _addressBytes32,
    uint256 _size
) internal pure returns (bytes memory result) {
    // Check if the specified size is valid (between 1 and 32 bytes)
    if (_size == 0 || _size > 32)
        revert AddressCast_InvalidSizeForAddress();

    // Create a new bytes memory array of the specified size
    result = new bytes(_size);

    // Perform the conversion using assembly
    unchecked {
+       // Validate the offset calculation before applying it
        uint256 offset = 256 - _size * 8;
+       require(offset >= 0 && offset <= 256, "Offset out of bounds");
        assembly {
            // Store the left-shifted bytes32 value in the result array
            mstore(add(result, 32), shl(offset, _addressBytes32))
        }
    }
}
```

### Mitigation:
1. **Additional Validation for Offset**: Before entering the unchecked block, validate the calculated offset to ensure that it is within the valid range and won’t lead to memory corruption.
2. **Careful Use of Unchecked**: Avoid using unchecked blocks unless absolutely necessary, and ensure that memory management operations are validated to prevent potential bugs or memory corruption.

### Impact:
- **Memory Corruption**: Improper handling of unchecked memory operations could lead to data corruption in the memory, which may cause unexpected contract behavior.



