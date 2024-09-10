## Title - [L-1] - Unsafe control flow construct in `utils.cairo::u128_bytes_len` and `utils::u128_fast_pow2`

## Impact
In `utils.cairo::u128_bytes_len` and `utils::u128_fast_pow2`, the long if statements can be counterproductive and can introduce errors which would lead to exploits that might allow a dos or other forms of attacks.   

## Proof of Concept
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/utils.cairo#L31

https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/utils.cairo#L67

## Tools Used
Manual review

## Recommended Mitigation Steps
Use the much safer `match` control flow construct to rewrite these statements.

