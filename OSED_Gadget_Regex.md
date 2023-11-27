# Quick Reference
Register placeholder: ```[A-Za-z]+```

Pointer Deference [register+offset]:  ```dword [[A-Za-z]+([+-]0x[0-9A-Fa-f]+)*\]```  


# Category
## Save Initial ESP
### push esp; Other instructions; pop REG1; ret;

Priority: `High`

RegEx: ```push esp(.*); pop [A-Za-z]+```

Description: The initial ESP is saved in register REG1.

Example: ```push esp; mov eax, ecx; pop esi;```

### push esp; pop REG1; ret;

Priority: `High`

RegEx: ```push esp; pop [A-Za-z]+;```

Description: The initial ESP is saved in register REG1.

### lea REG1, esp; ret;

Priority: `High`

RegEx: ```lea [A-Za-z]+, esp;```

Description: The initial ESP is saved om register REG1.

### lea REG1, [esp]; ret;

Priority: `High`

RegEx: ```lea [A-Za-z]+, \[esp\];```

Description: The initial ESP is saved om register REG1.

### lea REG1, [esp+offset]; ret;

Priority: `High`

RegEx: ```lea [A-Za-z]+, \[esp```

Description: The initial ESP with an offset is saved in register REG1.

Example: ```lea esi, [esp+4];```, register ESI stores the address `ESP+4`. After the gadget, we need to subtract 4 byte to get the initial ESP.

### mov REG1, esp; ret;

Priority: `High`

RegEx: ```mov [A-Za-z]+, esp;```

Description: Register REG1 saves the initial ESP.

### or REG1, esp;

Priority: `High`

RegEx: ```or [A-Za-z]+, esp;```

Description: Assume REG1 is zero already, then register REG1 saves the initial ESP.

Example: If a gadget like ```xor eax, eax; ret``` is used, then ```or eax, esp; ret;``` can be used to save initial ESP.

### xor REG1, esp;

Priority: `High`

RegEx: ```xor [A-Za-z]+, esp;```

Description: Assume REG1 is zero already, then register REG1 saves the initial ESP.

Example: If a gadget like ```xor eax, eax; ret``` is used, then ```xor eax, esp; ret;``` can be used to save initial ESP.

### add REG1, esp;

Priority: `High`

RegEx: ```add [A-Za-z]+, esp;```

Description: Assume REG1 is zero already, then register REG1 saves the initial ESP.

Example: If a gadget like ```xor eax, eax; ret``` is used, then ```add eax, esp; ret;``` can be used to save initial ESP.


### sub REG1, esp;

Priority: `High`

RegEx: ```sub [A-Za-z]+, esp;```

Description: Assume REG1 is zero already, then register REG1 saves the initial ESP.

Example: If a gadget like ```xor eax, eax; ret``` is used, then ```sub eax, esp; ret;``` and ```neg eax;``` can be used to save initial ESP.

    
## Pointer Dereference
### mov REG1, [REG+offset]; ret;

Priority: `High`

RegEx: ```mov [A-Za-z]+, dword [[A-Za-z]+([+-]0x[0-9A-Fa-f]+)*\]```

Description: Can be used to fetch an argument value.

Example: Assume ESI points to the `2rd` argument of function `VirtualAlloc`, ```mov eax, [esi+0x4];```, register EAX saves the value of `3rd` argument. 

## Write What Where
### mov [REG+offset], REG1; ret;

Priority: `High`

RegEx: ```mov dword [[A-Za-z]+([+-]0x[0-9A-Fa-f]+)*\], [A-Za-z]+```

Description: Can be used to patch an argument.

Example: Assume EAX points to the `2nd` argument of function VirtualAlloc, ```mov [eax+0x4], ecx;```, the 3rd argument is patched with the value stored in ECX.






## Swap Register
### mov REG1, REG2; ret;

Priority: `High`

RegEx: ```mov [A-Za-z]+, [A-Za-z]+;```

Description: Assign a value for a register.

Example: Register EAX saves the initial ESP, ```mov esi, eax;```, now register ESI backups the initial ESP, in case EAX will be overwritten in the following instructions.

### xchg REG1, REG2; ret;

Priority: `High`

RegEx: ```xchg [A-Za-z]+, [A-Za-z]+;```

Description: Exchange values stored in the 2 registers.

### push REG1; pop REG2; ret;

Priority: `High`

RegEx: ```push [A-Za-z]+; pop [A-Za-z]+;```

Description: Assign a value for a register. Similar to ```mov REG1, REG2;```.

### push REG1; other instructions; pop REG2; ret;

Priority: `High`

RegEx: ```push [A-Za-z]+(.*); pop [A-Za-z]+ ```

Description: The value stored in register REG1 is assigned to register REG2.





## +1
### inc REG1; ret;

Priority: `High`

RegEx: ```inc [A-Za-z]+;```

Description: Can be used to move to the next argument.

Example: Register EAX points to the 2nd argument of function VirtualAlloc, use the gadget ```inc eax; ret;``` 4 times to move to the 3rd argument.

### inc [REG1+offset]; ret;

Priority: `Medium`

RegEx: ```inc dword [[A-Za-z]+([+-]0x[0-9A-Fa-f]+)*\]```

Description: Can be used to change the value of an argument slightly.

Example: Assume EAX points to the 2nd argument, due to bad characters, the value of the 3rd argument is 0x0 on the stack now, use gadget ```inc [eax+0x4]; ret;``` to patch the value to `1`. 





## -1
### dec REG1; ret;

Priority: `Medium`

RegEx: ```dec [A-Za-z]+;```

Description: Can be used to move to the previous argument.

### dec [REG1+offset]; ret;

Priority: `Medium`

RegEx: ```dec dword [[A-Za-z]+([+-]0x[0-9A-Fa-f]+)*\]```

Description: Can be used to change the value of an argument slightly.





## Add Register
### add REG1, REG2; ret;

Priority: `High`

RegEx: ```add [A-Za-z]+, [A-Za-z]+;```

Description: Can be used to jump with an offset

Example: Assume EAX points to the 2nd argument of function VirtualAlloc, ECX saves the offset to reach the start of the shellcode. Use gadget ```add eax, ecx; ret;``` to jump to the shellcode area.

### add [REG1+offset], REG2; ret;

Priority: `High`

RegEx: ```add dword [[A-Za-z]+([+-]0x[0-9A-Fa-f]+)*\], [A-Za-z]+```

Description: Can be used to change the value of an argument.

Example: Assume EAX points to the 2nd argument of function VirtualAlloc, the 3rd argument is initialized with a placeholder value due to bad characters. RCX stores a value, use gadget ```add [eax+0x4], ecx; ret;``` to patch the 3rd argument.





## Sub Register
### sub REG1, REG2; ret;

Priority: `High`

RegEx: ```sub [A-Za-z]+, [A-Za-z]+;```

Description: Can be used to jump with an offset

### sub [REG1+offset], REG2; ret;

Priority: `High`

RegEx: ```sub dword [[A-Za-z]+([+-]0x[0-9A-Fa-f]+)*\], [A-Za-z]+;```

Description: Can be used to change the value of an argument.





## Negate Register
### neg REG1; ret;

Priority: `High`

RegEx: ```neg [A-Za-z]+;```

Description: Can be used to negate a fetched argument value.

Example: Assume ECX stores the value of an argument, to eliminate Null byte, the placeholder value is negated. Use gadget ```neg ecx; ret;``` to set the proper argument value.

### neg [REG1+offset]; ret;

Priority: `High`

RegEx: ```neg dword [[A-Za-z]+([+-]0x[0-9A-Fa-f]+)*\];```

Description: Can be used to directly negate the value of an argument.

Example: Assume EAX points to the 2nd argument of function VirtualAlloc, the value of the 3rd argument is negated. Use gadget ```neg [eax+0x4]; ret;``` to negate the value.





## Set Register 0
### xor REG1, REG1; ret;

Priority: `High`

RegEx: ```xor [A-Za-z]+, [A-Za-z]+;```

Description: If the value of an argument is 0x0, prepare the value before patching the argument.

Example: Assume the value of an argument should be 0x0, use gadget ```xor ecx, ecx; ret;``` to set ECX to 0x0 before patching the argument.

### SUB REG1, REG1; ret;

Priority: `Medium`

RegEx: ```sub [A-Za-z]+, [A-Za-z]+;```

Description: If the value of an argument is 0x0, prepare the value before patching the argument.

### lea [REG1], 0; ret;

Priority: `Medium`

RegEx: ```lea \[[A-Za-z]+\], (0)*(x)*(0)+;```

Description: If the value of an argument is 0x0, prepare the value before patching the argument.

### mov REG1, 0; ret;

Priority: `Medium`

RegEx: ```mov [A-Za-z]+, (0)*(x)*(0)+;```

Description: If the value of an argument is 0x0, prepare the value before patching the argument.

### and REG1, 0; ret;

Priority: `Medium`

RegEx: ```and [A-Za-z]+, (0)*(x)*(0)+;```

Description: If the value of an argument is 0x0, prepare the value before patching the argument.

### push 0; pop REG1; ret;

Priority: `Medium`

RegEx: ```push (0)*(x)*(0)+; pop [A-Za-z]+;```

Description: If the value of an argument is 0x0, prepare the value before patching the argument.





## pop
### pop REG1; ret;

Priority: `High`

RegEx: ```pop [A-Za-z]+;```

Description: Can be used to save a value prepared for an argument in a register,

Example: Before patching the value of an argument, use gadget ```pop ecx; ret;``` to set a value for ECX.





## Decode byte
### add [REG1+offset]; l-Reg2/h-Reg2; ret;

Priority: `High`

RegEx: ```add byte \[[A-Za-z]+([+-]0x[0-9A-Fa-f]+)*\]+, [A-Za-z]+```

Description: Decode a byte by adding a small value

Example: Use gadget ```add byte [eax], cl/ch; ret;```` to add cl/ch to the byte in [eax]

### sub [REG1+offset]; l-Reg2/h-Reg2; ret;

Priority: `High`

RegEx: ```sub byte \[[A-Za-z]+([+-]0x[0-9A-Fa-f]+)*\]+, [A-Za-z]+```

Description: Decode a byte by subbing a small value

Example: Use gadget ```sub byte [eax], cl/ch; ret;```` to sub cl/ch to the byte in [eax]




## Align EBP
### push REG1; pop ebp; ret;

Priority: `High`

RegEx: ```push [A-Za-z]+; pop ebp;```

Description: Can be used to align EBP with the function address.

Example: Assume register EAX points to the function address, use gadget ```push eax, ebp; ret``` to align EBP with the function address on the stack.

### xchg REG1, ebp; ret;

Priority: `High`

RegEx: ```xchg [A-Za-z]+, ebp;```

Description: Can be used to align EBP with the function address.

### xchg ebp, REG1; ret;

Priority: `High`

RegEx: ```xchg ebp, [A-Za-z]+;```

Description: Can be used to align EBP with the function address.

### push ebp; push REG1; pop REG2; pop REG3; ret;

Priority: `High`

RegEx: ```push ebp; push [A-Za-z]+; pop [A-Za-z]+; pop [A-Za-z]+;```

Description: Can be used to align EBP with the function address.





## EIP to ESP
### mov esp, ebp; pop ebp; ret;

Priority: `High`

RegEx: ```mov esp, ebp; pop ebp; ret;```

Description: Transfer the execution to ESP.

### leave; ret;

Priority: `High`

RegEx: ```leave;```

Description: It is equal to gadget ```mov esp, esp; pop ebp; ret```.

### mov esp, REG1; ret;

Priority: `High`

RegEx: ```mov esp, [A-Za-z]+;```

Description: Align ESP with the function address on the stack.

Example: Assume register EAX points to the function address on the stack, use gadget ```mov esp, eax; ret;``` to make ESP align with the function address as well.

### xchg REG1, esp; ret;

Priority: `High`

RegEx: ```xchg [A-Za-z]+, esp;```

Description: Align ESP with the function address on the stack.

### xchg esp; REG1; ret;

Priority: `High`

RegEx: ```xchg esp, [A-Za-z]+;```

Description: Align ESP with the function address on the stack.

