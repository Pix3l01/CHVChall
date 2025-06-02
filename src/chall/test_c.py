from ctypes import CDLL, c_uint64
from Crypto.Cipher import AES

from classes import SA_seed

KEY = bytes.fromhex("625d0457abaa2299a5b99b64db8e773803a2c67983c24a364a35b696a95bb51b")

seed = SA_seed(1).seed

# Encrypt the seed using AES-256 ecb
plaintext = seed + b'\x00' * (16 - len(seed))

cipher = AES.new(KEY, AES.MODE_ECB)
ciphertext = cipher.encrypt(plaintext)

# Take first 4 bytes and last 4 bytes
result_bytes = ciphertext[:4] + ciphertext[-4:]
result = int.from_bytes(result_bytes, byteorder='big')


lib = CDLL("./lib.so")
lib.seed_key.restype = c_uint64
gen_key = lib.seed_key(seed)

print(f"seed: {seed.hex()}\ngen_key: {hex(gen_key)}\nCiphertext: {ciphertext.hex()}\nResult: {hex(result)}")

#
# if gen_key < 0:
#     gen_key += 2 ** 32
# gen_key = gen_key.to_bytes(4, "big")
