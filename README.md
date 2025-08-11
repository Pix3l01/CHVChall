# Utterly Deranged Server

## CarHackingVillage CTF 2025 challenge

Capture the flag competiotion of the Car Hacking Village @ DEFCON 33, mainly focused on automotive systems security.

### Description

I’ve developed a super secure UDS server that hackers will never be able to exploit! Prove me wrong by reading DID `0x7A69` and win a big bounty flag. You can talk to the UDS server by using Tx ID `0x769`.

You must solve this challenge on the CHV floor to get the flag, but I provide you an online mirror to write and test your exploit at `52.9.34.196:9999`. In the attachments you'll find a client to connect to the remote instance and a readme explaining how the communication works in case you need/want to implement your own.

### Deploy

This challenge has both a local version that needs a Linux socketCAN interface to work and an online version. The docker compose files are provided for both version. Alternatively, the challenge can be run without containerization by looking  at the commands in [run.sh](src/chall/run.sh), given that the system package `can-utils` (and `socat` for the remote version) and the python module `scapy` are installed.

#### Local version
To create a local virtual can interface look at the instruction in the client. In the file [docker-compose-local.yaml](src/docker-compose-local.yaml) modify `can0`in the `command` section with the name of your local CAN interface and then start the challenge with the command: `docker compose -f path/to/docker-compose-local.yaml up --build -d` 

#### Remote version
Start the challenge with the command: `docker compose -f path/to/docker-compose-remote.yaml up --build -d`. The challenge will be available at `localhost:9999`

## Solution

Read the writeup at [src/solve/writeup.md](src/solve/writeup.md)

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
- [x] Better logging, if needed -> Don't need it, YOLO
- [x] Useless improvements: add jokes, ~~refactor, make it better...~~ -> only bad jokes 'cause I'm lazy 
- [x] Complete README
- [x] Longer waits for security access timeout
- [x] Client reconnection system/keepalive: not needed, for now
