from cryptopals import random_bytes, generate_aes_key, pkcs7_pad, \
						encrypt_aes_ecb, b64_string_to_bytearray
from random import randint

def c14():

	filename = '../data/12.txt'

	this_file = open(filename)
	b64_string = ''.join([x.rstrip('\n') for x in this_file.readlines()])
	unknown_string = str(b64_string_to_bytearray(b64_string))

	ecb_us_rp = ECBUnknownSuffixRandomPrefix(unknown_string)
	
	#Assume that we know block_size = 16 and mode = ECB
	#(TODO: detect these properties, as in C12)
	block_size = 16

	prefix_length = detect_prefix_length(ecb_us_rp.encrypt, block_size)

	known_bytes = ''
	while (True):
		next_byte = decrypt_next_byte(ecb_us_rp.encrypt, block_size, known_bytes, prefix_length)
		if not next_byte:
			break
		known_bytes += next_byte

	#The second last execution of decrypt_next_byte detects a trailing '\x01' 
	#added by PKCS#7 padding (the last execution then fails, as the '\x01'
	#has become a '\x02'). So this last char needs to be removed in the output.
	return known_bytes[:-1]

def detect_prefix_length(cipher, block_size):

	#To correctly detect prefix length, the last char of our crafted input 
	#must differ from the first char of the (unknown) suffix. To ensure this,
	#detect twice with different inputs and take the minimum
	size1 = detect_prefix_length_ci(cipher, block_size, 'A')
	size2 = detect_prefix_length_ci(cipher, block_size, 'B')
	return min(size1, size2)

def detect_prefix_length_ci(cipher, block_size, ci_char):

	blank_ct = cipher('')
	prev_ct = cipher(ci_char)
	prev_block_diff = find_block_diff(blank_ct, prev_ct, block_size)

	for i in range(2, block_size+2):
		pt = i * ci_char 
		curr_ct = cipher(pt)
		curr_block_diff = find_block_diff(prev_ct, curr_ct, block_size)
		if prev_block_diff != curr_block_diff:
			prefix_length = prev_block_diff * block_size + 16 - i + 1
			return prefix_length
		prev_ct = curr_ct

def find_block_diff(ct1, ct2, block_size):
	for (i,offset) in enumerate(range(0, max(len(ct1),len(ct2)), block_size)):
		if ct1[offset:offset+block_size] != ct2[offset:offset+block_size]:
			return i
	return -1

def decrypt_next_byte(cipher, block_size, known_bytes, prefix_length):

	CI_CHAR = 'A'

	#Synthesize input that aligns prefix to the block size
	prefix_align_length = -prefix_length % block_size
	aligned_prefix_length = prefix_length + prefix_align_length
	prefix_align_input = prefix_align_length * CI_CHAR

	#Synthesize input that aligns next unknown byte with end of block
	#(assuming prefix already aligned)
	target_align_length = -(len(known_bytes) + 1) % block_size
	target_align_input = target_align_length * CI_CHAR

	#Extract ciphertext for block with unknown byte in last position
	ct = cipher(prefix_align_input + target_align_input)[aligned_prefix_length:]
	block_num = len(known_bytes) / block_size
	block_ct = ct[(block_num * block_size):((block_num+1) * block_size)]

	#Test against all possible last bytes to identify unknown byte
	block_1_short = (target_align_input + known_bytes)[-(block_size-1):]
	for i in range(0, 256):
		candidate_block = block_1_short + chr(i)
		ct = cipher(prefix_align_input + candidate_block)[aligned_prefix_length:]
		candidate_block_ct = ct[0:block_size]
		if (block_ct == candidate_block_ct):
			return chr(i)

class ECBUnknownSuffixRandomPrefix:
	def __init__(self, unknown_string):
		PREFIX_MAX_LEN = 100
		self._key = generate_aes_key()
		self._random_prefix = random_bytes(randint(0,PREFIX_MAX_LEN))
		self._unknown_string = unknown_string

	def encrypt(self, your_string):
		plaintext = self._random_prefix + your_string + self._unknown_string
		plaintext = pkcs7_pad(plaintext, 16)

		ciphertext = encrypt_aes_ecb(plaintext, self._key)
		return ciphertext

if __name__ == "__main__":
	print c14()
