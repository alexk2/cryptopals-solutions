from Crypto.Cipher import AES
import random

def hex_string_to_bytearray(hex_string):
	
	#Pad hex string to multiple of 2 chars = 8 bits
	padding_length = -len(hex_string) % 2
	hex_string = padding_length * '0' + hex_string

	hex_int_list = [hex_char_to_int(x) for x in hex_string]
	this_bytearray = bytearray()
	#Convert hex digits to bytes in 2 hex digit chunks
	for i in range(0, len(hex_int_list)/2):
		h = hex_int_list[2*i:2*i+2]
		b = (h[0] << 4) + h[1]
		this_bytearray.append(b)

	return this_bytearray

def bytearray_to_hex_string(this_bytearray):

	hex_index = "0123456789abcdef"

	hex_int_list = []
	h = 2 * [0]
	for i in range(0, len(this_bytearray)):
		b = this_bytearray[i]
		h[0] = b >> 4
		h[1] = b & 15
		hex_int_list.extend(h)

	hex_string = ''.join([hex_index[x] for x in hex_int_list])
	return hex_string

def b64_string_to_bytearray(b64_string):

	b64_index = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	b64_string = b64_string.rstrip('=')
	#Pad b64 string to multiple of 4 b64 digits = 24 bits (= lcm(8,6))
	padding_length = -len(b64_string) % 4
	b64_string += padding_length * b64_index[0]

	b64_int_list = [b64_index.index(x) for x in b64_string]
	this_bytearray = bytearray()
	b = bytearray(3)
	#Convert b64 digits to bytes in 4 b64 digit chunks
	for i in range(0, len(b64_int_list)/4):
		b64 = b64_int_list[4*i:4*(i+1)]
		b[0] = (b64[0] << 2) | (b64[1] >> 4)
		b[1] = ((b64[1] << 4) | (b64[2] >> 2)) & 255
		b[2] = ((b64[2] << 6) | b64[3]) & 255
		this_bytearray.extend(b)

	#Trim extra chars produced by padding
	this_bytearray = this_bytearray[0:len(this_bytearray) - padding_length]
	return this_bytearray

def bytearray_to_b64_string(this_bytearray):

	b64_index = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	#Pad bytearray to multiple of 3 bytes = 24 bits (= lcm(8,6))
	padding_length = -len(this_bytearray) % 3
	this_bytearray += padding_length * '\0'

	b64_int_list = []
	b64 = 4 * [0]
	#Convert bytes to b64 digits in 3 byte chunks	
	for i in range(0, len(this_bytearray)/3):
		b = this_bytearray[3*i:3*i+3]
		b64[0] = b[0] >> 2
		b64[1] = ((b[0] << 4) + (b[1] >> 4)) & 63
		b64[2] = ((b[1] << 2) + (b[2] >> 6)) & 63
		b64[3] = b[2] & 63
		b64_int_list.extend(b64)

	b64_string = ''.join([b64_index[x] for x in b64_int_list])
	#Replace extra chars produced by padding with '=' padding chars
	b64_string = b64_string[0:len(b64_string) - padding_length]
	b64_string += padding_length * '='
	return b64_string

def hex_char_to_int(hex_char):
	if '0' <= hex_char and hex_char <= '9':
		return ord(hex_char) - ord('0')
	if 'a' <= hex_char and hex_char <= 'f':
		return 10 + ord(hex_char) - ord('a')
	if 'A' <= hex_char and hex_char <= 'F':
		return 10 + ord(hex_char) - ord('A')
	raise Exception("Invalid input")

def bytearray_xor(ba1, ba2):
	if len(ba1) != len(ba2):
		raise Exception("Input bytearrays not equal length")

	result = bytearray()
	for (b1,b2) in zip(ba1,ba2):
		result.append(b1 ^ b2)

	return result

def string_xor(s1, s2):
	if len(s1) != len(s2):
		raise Exception("Input strings not equal length")

	result = bytearray()
	for (c1,c2) in zip(s1,s2):
		result.append(ord(c1) ^ ord(c2))

	return str(result)

def decrypt_sb_xor(ba):
	frequent_chars = "ETAOIN SHRDLU"
	frequent_chars += frequent_chars.lower()

	scores = 256 * [0]
	for i in range(0,256):
		cipher = bytearray(len(ba) * [i])
		ba_dec = bytearray_xor(ba, cipher)
		scores[i] = [chr(x) in frequent_chars for x in ba_dec].count(True)

	best_score = max(scores)
	best_byte = scores.index(best_score)

	cipher = bytearray(len(ba) * [best_byte])
	ba_dec = bytearray_xor(ba, cipher)
	return (ba_dec, best_byte, best_score)

def encrypt_rk_xor(plaintext_ba, key_ba):
	key_len = len(key_ba)
	ba_enc = [x ^ key_ba[i % key_len] for (i,x) in enumerate(plaintext_ba)]
	return bytearray(ba_enc)

def hamming_distance(s1, s2):
	ba1 = bytearray(s1)
	ba2 = bytearray(s2)
	distance = sum([bit_count(b1 ^ b2) for (b1,b2) in zip(ba1,ba2)])
	return distance

def bit_count(i):
	distance = 0
	while i != 0:
		distance += (i & 1)
		i = i >> 1
	return distance

def pkcs7_pad(s, block_length):
	padding_length = block_length - len(s) % block_length
	s_padded = s + padding_length * chr(padding_length)
	return s_padded

def pkcs7_strip(s):
	pkcs7_len = ord(s[-1])
	return s[:-pkcs7_len]

def pkcs7_validate_strip(s):
	if len(s) == 0:
		return s
	pkcs7_len = ord(s[-1])
	pkcs7_padding = s[-pkcs7_len:]
	if all([ord(x) == pkcs7_len for x in pkcs7_padding]):
		return s[:-pkcs7_len]
	else:
		raise Exception('String ' + repr(s) + ' has invalid padding')

def encrypt_aes_ecb(plaintext, key):
	cipher = AES.new(key, AES.MODE_ECB)
	ciphertext = cipher.encrypt(plaintext)
	return ciphertext

def decrypt_aes_ecb(ciphertext, key):
	cipher = AES.new(key, AES.MODE_ECB)
	plaintext = cipher.decrypt(ciphertext)
	return plaintext

def encrypt_aes_cbc(plaintext, key, iv):

	ciphertext = bytearray()
	prev_block_enc = iv
	for i in range(0,len(plaintext),16):
		block = plaintext[i:i+16]
		block_chained = string_xor(block, prev_block_enc)
		block_enc = encrypt_aes_ecb(block_chained, key)
		ciphertext.extend(block_enc)
		prev_block_enc = block_enc

	return str(ciphertext)

def decrypt_aes_cbc(ciphertext, key, iv):

	plaintext = bytearray()
	prev_block_enc = iv
	for i in range(0,len(ciphertext),16):
		block_enc = ciphertext[i:i+16]
		block_chained = decrypt_aes_ecb(block_enc, key)
		block = string_xor(block_chained, prev_block_enc)
		plaintext.extend(block)
		prev_block_enc = block_enc
		
	return str(plaintext)

def random_bytes(n):
	return ''.join([chr(random.randint(0,255)) for x in range(0,n)])

def generate_aes_key():
	return random_bytes(16)

def encryption_oracle(plaintext):
	pre_bytes = random_bytes(random.randint(5,10))
	post_bytes = random_bytes(random.randint(5,10))
	plaintext = pre_bytes + plaintext + post_bytes
	plaintext = pkcs7_pad(plaintext, 16)

	key = generate_aes_key()

	if random.randint(0,1) == 1:
		mode = "ECB"
		ciphertext = encrypt_aes_ecb(plaintext, key)
	else:
		mode = "CBC"
		iv = random_bytes(16)
		ciphertext = encrypt_aes_cbc(plaintext, key, iv)

	return (mode, ciphertext)

def detect_cipher_mode(black_box):
	#Length chosen to ensure blocks 2 and 3 are from plaintext
	pt_length = 43
	plaintext = pt_length * '\0'

	(mode, ciphertext) = black_box(plaintext)

	#Blocks 2 and 3 contain the same plaintext, so their corresponding
	#ciphertext will be the same under ECB, and different under CBC
	block2 = ciphertext[16:32]
	block3 = ciphertext[32:48]
	if block2 == block3:
		detected_mode = "ECB"
	else:
		detected_mode = "CBC"

	return (mode, detected_mode)

class ECBUnknownSuffix:
	def __init__(self, unknown_string):
		self._key = generate_aes_key()
		self._unknown_string = unknown_string

	def encrypt(self, your_string):
		plaintext = your_string + self._unknown_string
		plaintext = pkcs7_pad(plaintext, 16)

		ciphertext = encrypt_aes_ecb(plaintext, self._key)
		return ciphertext
