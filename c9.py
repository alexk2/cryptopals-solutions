from mcc_helpers import pkcs7_pad

def c9(s, block_length):
	return pkcs7_pad(s, block_length)

if __name__ == "__main__":
	s = "YELLOW SUBMARINE"
	block_length = 20
	print repr(c9(s, block_length))
