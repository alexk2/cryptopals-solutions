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
	return (ba_dec, best_score)

def encrypt_rk_xor(plaintext_ba, key_ba):
	key_len = len(key_ba)
	ba_enc = [x ^ key_ba[i % key_len] for (i,x) in enumerate(plaintext_ba)]
	return ba_enc
