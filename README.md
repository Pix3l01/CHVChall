# Utterly Deranged Server

## CarHackingVillage CTF 2025 challenge

TODO: couple of words about ctf

### Description

I’ve developed a super secure UDS server that hackers will never be able to exploit! Prove me wrong by reading DID `0x7A69` and win a big bounty flag. You can talk to the UDS server by using Tx ID `0x769`.

You must solve this challenge on the CHV floor to get the flag, but I provide you an online mirror to write and test your exploit at `domain:port`. In the attachments you'll find a client to connect to the remote instance and a readme explaining how the communication works in case you need/want to implement your own.

### Deploy

TODO

## Solution

TODO

## Other

### Idea

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

### ROADMAP

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
- [x] Add description (remember to use the correct IDs) and name
- [x] Modify CAN IDs to 0x769 and 0x742
- [X] Implement instancer (try with a CAN over IP)
  - [X] Multiple steps which I'll think about later 
- [x] Add socat timeout. Not putting it for now, hope that people behaves
- [x] Add readme for client and move to handount folder or similar
- [x] Modify ip/hostname and port in client, readme and socat command (once these data are known)
- [x] Think of a flag: DONE, look at CFC document
- [ ] Better logging, if needed
- [ ] Useless improvements: add jokes, refactor, make it better...
- [ ] Complete README
- [x] Longer waits for security access timeout
- [x] Client reconnection system/keepalive: not needed, for now
