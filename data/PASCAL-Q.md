1.
 In `settlement.cairo`, `check_chakra_signatures()`there is no need to loop through all the signatures passed, once it gets the current required number of validator signatures the loop should break butin the current implementation it loops through every single signature passed.
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/settlement.cairo#L173-L189

2. 
In `settlement.cairo`, `set_required_validators_num()` does not check if the new number of require validator signature being set is more than the current validators. Example seting 5 signatures required when in actuality there's only three validators 
https://github.com/code-423n4/2024-08-chakra/blob/d0d45ae1d26ca1b87034e67180fac07ce9642fd9/cairo/handler/src/settlement.cairo#L197-L202





