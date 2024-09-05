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