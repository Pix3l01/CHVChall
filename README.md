# CHV Challenge

## Idea

Challenge on UDS on CAN
1. Recon:
    - 3 sessions (1,2,3)
    - Multiple services for each session
    - DID 0xf132 which contains active session can be modified
    - In session 3 RMBA can be called without authN and leaks memory
2. Memory leak contains code for SA key verification
3. Reverse:
    - Different algorithms for session 2 and 3
    - Session 2 is AES but dont know the key
    - Session 3 is just bytes manipulation that can be reversed
    - Algorithm chosen based on value of variable at memory address 0xYYYYYF132, which is the same address as modifiable DID
4. Exploit:
    - Go to session 2
    - Modify DID 0xf132 to change active session to 3
    - Do SA and use session 3 algorithm to generate SA key
    - Read flag DID

## ROADMAP

- [x] Port basic UDS emulator
- [x] Implement vulnerable WDBI
- [x] Remove global variable for session tracking and only use data from the DIDs dictionary
- [x] Write code for SA key check
  - [x] C code
  - [x] Python code
- [x] Generate check function for leak
- [x] Write python code to exploit the vulnerability
  - [x] Memory leak
  - [x] Get flag
- [ ] Add description and name
- [ ] Modify CAN IDs to 0x769 and 0x742
- [ ] Implement instancer (try with a CAN over IP)
  - [ ] Multiple steps which I'll think about later 
- [ ] Useless improvements: add jokes, refactor, make it better...
