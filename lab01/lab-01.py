import base64
import tempfile
print ("Solution for Lab-1\n************************************\n")

## Module-1: Format conversion
print ("Example-1: Hexadecimal representation\n")
hello_string = "hello".encode('utf-8')
hex_hello = hello_string.hex()
print ("The hexadecimal representation for hello is:",hex_hello,"\n\n")

### Base64 encoding is a type of conversion of bytes into ASCII characters.
print ("Example-2: Base 64 encoding\n")
example_string = "base64 encoded string".encode('utf-8')
encoded = base64.b64encode(example_string)
print ("The base 64 encoding for \'base64 encoded string\' is:",encoded,"\n")
print("(The b\'...\' indicates base 64 representation)\n\n")
# print(encoded)
# print ('YmFzZTY0IGVuY29kZWQgc3RyaW5n')

print ("Format Conversion-1\n")
string = "Karma police, arrest this man, he talks in maths"
xor_string = "".join([chr(ord(char) ^ 0x01) for char in string])
b64_string = base64.b64encode(xor_string.encode('utf-8'))

print("Key:0x01","\n")
print("Plaintext:",string,"\n")
print ("Ciphertext:",b64_string,"\n\n")

fh = tempfile.TemporaryFile()
fh.write(b64_string)
fh.close()

## Module-2: Single-byte XOR cipher

print ("Format Conversion-2\n")
encrypted_string = "210e09060b0b1e4b4714080a02080902470b0213470a0247081213470801470a1e4704060002"
decode_string = bytes.fromhex(encrypted_string).decode('utf-8')
best = None
for key in range(256):
	list_string = [ord(char)^ key for char in decode_string]
	num_spaces = list_string.count(ord(' '))
	guess_plain = "".join([chr(ord(char) ^ key) for char in decode_string])	
	if best == None:
		best = hex(key), guess_plain, num_spaces
	elif best[2] < num_spaces:
		best = hex(key), guess_plain, num_spaces
print ("Ciphertext:",encrypted_string,"\n")
print ("Retrieved Key:",best[0],"\n")
print ("Retrieved Plaintext:",best[1],"\n")
print("We used the number of spaces in the decrypted string to guess the plaintext. Feel free to try out other ways for arriving at the same guess.\n")

# Module-3: Encrypting Using One Time Pads
import os

nlc_string = "Pay no mind to the distant thunder, Beauty fills his head with wonder, boy"

def xor_string_bytes_return_string(bytes_one, bytes_two):
	xor_set = []
	for i in range(len(bytes_one)):
		xor_value = chr(ord(bytes_one[i]) ^ bytes_two[i])
		xor_set.append(xor_value)
	string = "".join(xor_set)
	return string

def otp_encryption(plaintext):
	lenPtxt = len(plaintext)
	otp_string = os.urandom(lenPtxt)
	ciph_string = xor_string_bytes_return_string(plaintext, otp_string)
	return ciph_string, otp_string

def otp_decryption(ciphertext, otp):
	ptxt_string = xor_string_bytes_return_string(ciphertext, otp)
	return ptxt_string

ciphertext, otp = otp_encryption(nlc_string)
plaintext = otp_decryption(ciphertext, otp)
#print("ciphertext:", ciphertext,"\n")
#print("plaintext:", plaintext,"\n")

# Module-4: Two Time Pad
ctxt_one_string = "542055804aac960f97963f3a649e48335df8631c4a7a6b4500a5c7ec8573ea89970b296b50b491ca0d0ae14e6e0bd7f9d06a5db3e405bd53c1960bcd810b278b4acf12a1205c59263d"
ctxt_two_string = "2f7442c908accf0fd1d76b7f75ca1f7f0bf839455e3b304550e19ea3c57fffcfd047766b0af28299545fbf0a7c4a81bdc72c1ce1aa05ff1a95d8578bca427fcc5c814ff57c150e6124"

def xor_two_bytewise(array_one, array_two):
	lenString = max(len(array_one),len(array_two))
	xor_set = []
	for i in range(lenString):
		xor_value = chr(array_one[i] ^ array_two[i])
		xor_set.append(xor_value)
	xor_string = "".join(xor_set)
	return xor_string

def xor_two_strings(string_one, string_two):
	lenString = max(len(string_one), len(string_two))
	xor_set = []
	for i in range(lenString):
		xor_value = chr(ord(string_one[i]) ^ ord(string_two[i]))
		xor_set.append(xor_value)
	xor_string = "".join(xor_set)
	return xor_string

# string to hex byte
dec_ctxt_one  = bytes.fromhex(ctxt_one_string)
dec_ctxt_two = bytes.fromhex(ctxt_two_string)

# XOR CIPHERTEXTS TOGETHER
xored_ctxts_string = xor_two_bytewise(dec_ctxt_one, dec_ctxt_two)

## FIND LENGTH OF CTXTS, CREATE STRING OF KNOWN PLAINTEXT
#len_xored_ctxts = len(xored_ctxts_string)
#space_string = ' ' * len_xored_ctxts

## DECODE FROM SPACE STRING
#ds_ptxt = space_string.encode('utf-8')

## XOR KNOWN PLAINTEXT AND XORED CIPHERTEXTS TOGETHER
#half_ptxt_one = xor_two_strings(xored_ctxts_string, space_string)

## ENCODE INTO ASCII AND REPLACE FOR READABILITY
#df_ptxt = half_ptxt_one.encode('utf-8')

#print("50% PTXT ONE + 50% PTXT ONE XOR PTXT TWO: " + str(df_ptxt))

answer_string = "It is a tale told by an idiot, full of sound and fury signifying nothing."
ptxt_two = xor_two_strings(xored_ctxts_string, answer_string)

print("Plaintext One: "+answer_string)
print("Plaintext Two: "+ptxt_two)
