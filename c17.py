from mcc_helpers import generate_aes_key, random_bytes, encrypt_aes_cbc, \
						decrypt_aes_cbc, pkcs7_pad, pkcs7_strip
import random

def c17():

	oracle = CBCPaddingOracle()
	(token_ct, iv) = oracle.get_token()

	return oracle.check_token_padding(token_ct, iv)

class CBCPaddingOracle:

	B64_STRING_FILE = './17.txt'
	BLOCK_SIZE = 16

	def __init__(self):

		self._key = generate_aes_key()

		this_file = open(CBCPaddingOracle.B64_STRING_FILE)
		self._b64_strings = [x.rstrip('\n') for x in this_file.readlines()]

	def get_token(self):

		if len(self._b64_strings) == 0:
			raise Exception("No tokens available")

		token = self._b64_strings[random.randint(0,len(self._b64_strings)-1)]
		iv = random_bytes(CBCPaddingOracle.BLOCK_SIZE)
		token_ct = encrypt_aes_cbc(pkcs7_pad(token, CBCPaddingOracle.BLOCK_SIZE), \
			self._key, iv)
		return (token_ct, iv)

	def check_token_padding(self, token_ct, iv):

		token_padded = decrypt_aes_cbc(token_ct, self._key, iv)

		try:
			pkcs7_strip(token_padded)
		except Exception:
			return False

		return True


if __name__ == "__main__":
	print c17()
