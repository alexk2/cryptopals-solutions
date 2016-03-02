from mcc_helpers import b64_string_to_bytearray
from mcc_helpers import decrypt_aes_cbc

def c10():

	filename = './10.txt'
	key = 'YELLOW SUBMARINE'
	iv = 16 * '\0'

	this_file = open(filename)
	b64_string = ''.join([x.rstrip('\n') for x in this_file.readlines()])
	ciphertext = str(b64_string_to_bytearray(b64_string))

	plaintext = decrypt_aes_cbc(ciphertext, key, iv)
	return plaintext

if __name__ == "__main__":
	print c10()
