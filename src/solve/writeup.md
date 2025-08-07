# Writeup
The goal is to read the DID 0x7A69. There are four main steps to sole this challenge.

## Recon phase
We already know that it's UDS and that the Tx CAN ID is 0x769. So we can go straight to do a scan for sessions and services.

The main takeaways are the following:
1. There are 3 sessions (1,2 & 3)
2. Session 1 can only access session 3, session 2 can only access session 3, and session 3 can access both session 1 and 2
3. The flag DID can only be read in session 2 after a security access
4. DID 0xF132 probably holds the active session and can be modified in sessions 2 & 3
5. In session 3, the service 0x23 ReadMemoryByAddress can be called without authentication

## Memory leak
Using the service 0x23 ReadMemoryByAddress in session 3, part of the memory can be leaked. It's not the whole firmware, but a single function. The leaked memory around the compiled function contains 2 hints:
1. `Did you lock yourself out without the keys?` Hinting at the fact that the function is related to the seed&key
2. `x86:LE:64:gcc` specifies the architecture for which the function was compiled

The compiled bytes, between the two aforementioned hint strings, can be extracted and loaded into any disassembler/decompiler (eg: Ghidra).

[leak.py](leak.py) is a python script that leaks the aforementioned memory

## Reverse
The leaked function is the key generation function and takes the seed as a parameter. The main takeaways are the following:
1. Based on the value read at 0x0040f132, the function does two different operations on the seed
2. In the leak, the memory area 0x0040f132 is not present, but it can be assumed that it's the mapping for the DID 0xf132. So, the algorithm used to compute the key is chosen based on the active session
3. In session 2, the key is generated  by doing some unknown operations on the seed which are not present in the leak, so it can't be reversed. (It's AES with a secure random key)
4. In session 3, however, the key gets generated with known operation on the seed, so it can be wholly reversed and reimplemented from scratch (LLMs do a great job)

## Exploit
All the pieces are available, we just need to put them together:
1. Go to session 2
2. Modify DID 0xF132 to make the keygen function use the less secure algorithm
3. Do SecurityAccess
4. Read the flag DID

[get_flag.py](get_flag.py) is a python script that implements the exploit to get the flag

