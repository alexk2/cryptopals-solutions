from mcc_helpers import generate_aes_key, random_bytes, pkcs7_pad, \
						pkcs7_strip, encrypt_aes_cbc, decrypt_aes_cbc
import urllib

def c16():

	CI_CHAR = 'A'
	NEW_STRING = ';admin=true'
	BLOCK_SIZE = 16
	#Assume prefix length is known, and a multiple of the block size
	#(This could be detected and, if necessary, aligned to block boundaries
	#using similar techniques as in C14)
	OFFSET = 32 

	target = CBCBitFlipTarget()

	#Crafted input is a 'scramble' block, followed by a 'canvas' string with the 
	#same length as the string to be inserted. The 'scramble' block will be 
	#modified to induce appropriate bit flips in the 'canvas' string
	scramble_block = BLOCK_SIZE * CI_CHAR
	canvas_string = len(NEW_STRING) * CI_CHAR
	ci = scramble_block + canvas_string

	ct = target.encrypt(ci)
	ct_ba = bytearray(ct)

	#Create bit errors in the 'scramble' block in bit positions where the
	#inserted string and the 'canvas' string differ
	for i in range(0, len(NEW_STRING)):
		ct_ba[OFFSET+i] = ct_ba[OFFSET+i] ^ ord(CI_CHAR) ^ ord(NEW_STRING[i])

	ct = str(ct_ba)
	return (target.check_admin(ct), target.decrypt(ct))

class CBCBitFlipTarget:

	PREFIX = "comment1=cooking%20MCs;userdata="
	SUFFIX = ";comment2=%20like%20a%20pound%20of%20bacon"
	BS = 16

	def __init__(self):
		self._key = generate_aes_key()
		self._iv = random_bytes(CBCBitFlipTarget.BS)

	def encrypt(self, s):
		pt = CBCBitFlipTarget.PREFIX + urllib.quote(s) + CBCBitFlipTarget.SUFFIX
		ct = encrypt_aes_cbc(pkcs7_pad(pt, CBCBitFlipTarget.BS), self._key, self._iv)
		return ct

	def decrypt(self, ct):
		pt = pkcs7_strip(decrypt_aes_cbc(ct, self._key, self._iv))
		return pt

	def check_admin(self, ct):
		pt = pkcs7_strip(decrypt_aes_cbc(ct, self._key, self._iv))
		kvs = [x.split('=') for x in pt.split(';')]
		for kv in kvs:
			if len(kv) == 2 and kv[0] == 'admin' and kv[1] == 'true':
				return True
		return False

if __name__ == "__main__":
	(admin_status, new_pt) = c16()
	print "Admin Status: " + str(admin_status)
	print "New Plaintext: " + repr(new_pt)
