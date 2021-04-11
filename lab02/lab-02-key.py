import random
import os

from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes

## USEFUL FUNCTIONS
# integer_seed = int.from_bytes(key_seed, byteorder='big')
# key_seed = (integer_seed).to_bytes(2, byteorder='big')

PLAINTEXT = "Tracing one warm line through a land so wild and savage and make a Northwest Passage to the sea."
CIPHERTEXT = "05b4a85063e12931ce340321eb5141b24ee81ed6c10e9eae8991198ac796f4ff019aa75aabdd24ec2c6145d879c88faefb38563b870b65b87f3ce522e065fcf93bd0c6b60398724364ed7da5b17a2c042205628330e42e4a9c5bccfc3645b54d"
CONST_SEED = 25063
CONST_IV = "e764ea639dc187d058554645ed1714d8"
CONST_KEY = "d66b33940c9092dfef181797998b573e"
SEED_SIZE = 2
KEY_SIZE = 16

def generate_aes_key_from_int(integer, key_length):
	seed = (integer).to_bytes(2, byteorder='big')
	hash_object = SHA256.new(seed)
	aes_key = hash_object.digest()
	trunc_key = aes_key[:key_length]
	return trunc_key

def aes_cbc_encryption(plaintext, key, iv):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	ciphertext = cipher.encrypt(plaintext)
	return ciphertext

def aes_cbc_decryption(ciphertext, key, iv):
	cipher = AES.new(key, AES.MODE_CBC, iv)
	plaintext = cipher.decrypt(ciphertext)
	return plaintext

def decrypt_ciphertext(ciphertext, iv, key_size):
	best = None
	for key in range(1<<16):
		aes_key = generate_aes_key_from_int(key, key_size)
		plaintext = aes_cbc_decryption(ciphertext, aes_key, iv)
		num_spaces = plaintext.count(ord(' '))
		if best == None:
			best = key, plaintext, num_spaces
		elif best[2] < num_spaces:
			best = key, plaintext, num_spaces
	return best

plaintext = decrypt_ciphertext(bytes.fromhex(CIPHERTEXT), bytes.fromhex(CONST_IV), KEY_SIZE)
print (plaintext)
