from mcc_helpers import ECBUnknownSuffix
from mcc_helpers import b64_string_to_bytearray

def c12():

	filename = './12.txt'

	this_file = open(filename)
	b64_string = ''.join([x.rstrip('\n') for x in this_file.readlines()])
	unknown_string = str(b64_string_to_bytearray(b64_string))

	ecb_us = ECBUnknownSuffix(unknown_string)

	block_size = detect_block_size(ecb_us.encrypt)
	mode = detect_cipher_mode(ecb_us.encrypt, block_size)

	known_bytes = ''
	while (True):
		next_byte = decrypt_next_byte(ecb_us.encrypt, block_size, known_bytes)
		if not next_byte:
			break
		known_bytes += next_byte

	#The second last execution of decrypt_next_byte detects a trailing '\x01' 
	#added by PKCS#7 padding (the last execution then fails, as the '\x01'
	#has become a '\x02'). So this last char needs to be removed in the output.
	return known_bytes[:-1]

def detect_block_size(cipher):

	#To correctly detect block size, the last char of our prefix must
	#differ from the first char of the (unknown) suffix. To ensure this,
	#detect twice with different prefixes and take the maximum
	size1 = detect_block_size_prefix(cipher, 'A')
	size2 = detect_block_size_prefix(cipher, 'B')
	return max(size1, size2)

def detect_block_size_prefix(cipher, prefix_char):
	
	MAX_BLOCK_SIZE = 1024

	ct = cipher(prefix_char)
	b1_candidate = ct[0]
	for i in range(2, MAX_BLOCK_SIZE):
		pt = i * prefix_char
		ct = cipher(pt)
		if b1_candidate == ct[0:i-1]:
			return i-1
		b1_candidate = ct[0:i]
	
	raise Exception("Block size exceeds maximum of " + str(MAX_BLOCK_SIZE))

def detect_cipher_mode(cipher, block_size):

	pt = 2 * block_size * '\0'
	ct = cipher(pt)

	#Blocks 1 and 2 contain the same plaintext, so their corresponding
	#ciphertext will be the same under ECB, and different under CBC
	block1 = ct[0:16]
	block2 = ct[16:32]
	if block1 == block2:
		detected_mode = "ECB"
	else:
		detected_mode = "CBC"

	return detected_mode

def decrypt_next_byte(cipher, block_size, known_bytes):

	PREFIX_CHAR = 'A'
	prefix_length = -(len(known_bytes) + 1) % block_size
	crafted_input = prefix_length * PREFIX_CHAR

	block_1_short = (crafted_input + known_bytes)[-(block_size-1):]

	ct = cipher(crafted_input)
	block_num = len(known_bytes) / block_size
	block_ct = ct[(block_num * block_size):((block_num+1) * block_size)]

	for i in range(0, 256):
		candidate_block = block_1_short + chr(i)
		ct = cipher(candidate_block)
		candidate_block_ct = ct[0:block_size]
		if (block_ct == candidate_block_ct):
			return chr(i)

if __name__ == "__main__":
	print c12()
