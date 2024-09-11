### Missing Zero Address Check in `ckr_btc.cairo`

**Issue**:  
The contract is missing a zero address check in several critical functions, allowing a user to set contract addresses as zero (`0x0`), which can result in unintended behavior. The affected locations are:

---

1. **In Constructor**:  
   The constructor allows `owner` to be set as the zero address without validation.

   ```cairo
   // @audit owner can be a zero address
   self.chakra_managers.write(owner, 1);
   ```

   **Location**:  
   [ckr_btc.cairo#L79](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/ckr_btc.cairo#L79)

---

2. **In `add_manager` function**:  
   There is no check to prevent a zero address from being added as a manager.

   ```cairo
   // @audit missing zero address check
   self.chakra_managers.write(manager, 1);
   ```

   **Location**:  
   [ckr_btc.cairo#L139](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/ckr_btc.cairo#L139)

---

3. **In `remove_manager` function**:  
   There is no check to prevent attempting to remove a zero address.

   ```cairo
   // @audit missing zero address check
   self.chakra_managers.write(manager, 0);
   ```

   **Location**:  
   [ckr_btc.cairo#L148](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/ckr_btc.cairo#L151)

---

4. **In `add_operator` function**:  
   There is no check to prevent a zero address from being added as an operator.

   ```cairo
   // @audit missing zero address check
   self.chakra_operators.write(operator, 1);
   ```

   **Location**:  
   [ckr_btc.cairo#L169](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/ckr_btc.cairo#L174)

---

5. **In `remove_operator` function**:  
   There is no check to prevent attempting to remove a zero address.

   ```cairo
   // @audit missing zero address check
   self.chakra_operators.write(operator, 0);
   ```

   **Location**:  
   [ckr_btc.cairo#L181](https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/ckr_btc.cairo#L185)

---

### Recommended Fix:  
Add a check to prevent the zero address from being used in each of these functions. Below is an example of how to implement the check:

```cairo
// Check for zero address before writing to the map
if owner == 0 {
    // handle error, return or revert
    return;
}
self.chakra_managers.write(owner, 1);
```

Repeat similar checks in `add_manager`, `remove_manager`, `add_operator`, and `remove_operator` to ensure zero addresses are not used inappropriately.