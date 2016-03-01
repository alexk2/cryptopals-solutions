from Crypto.Cipher import AES
from mcc_helpers import b64_string_to_bytearray

def c7(filename, key):

	this_file = open(filename)
	b64_string = ''.join([x.rstrip('\n') for x in this_file.readlines()])
	this_bytearray = b64_string_to_bytearray(b64_string)

	cipher = AES.new(key, AES.MODE_ECB)
	plaintext = cipher.decrypt(str(this_bytearray))

	return plaintext

if __name__ == "__main__":
	filename = './7.txt'
	key = "YELLOW SUBMARINE"
	print c7(filename, key)
