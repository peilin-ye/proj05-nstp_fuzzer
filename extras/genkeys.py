#!/usr/env/python3
# genkeys.py
# generate random key pair and store them in "./keys"

import nacl.bindings

pkclient, skclient = nacl.bindings.crypto_kx_keypair()
print("public: ", pkclient)
print("secret: ", skclient)

# The first 32 bytes will be the public key, while the last 32 bytes will be the secret key
with open("./keys", "wb") as f:
	f.write(pkclient)
	f.write(skclient)

print("keys saved to \"./keys\"")
