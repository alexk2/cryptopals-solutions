from mcc_helpers import hex_string_to_bytearray
from mcc_helpers import decrypt_sb_xor

def c4(filename):
	this_file = open(filename)
	hex_strings = [x.rstrip('\n') for x in this_file.readlines()]
	bytearrays = [hex_string_to_bytearray(x) for x in hex_strings]

	candidates = [decrypt_sb_xor(x) for x in bytearrays]
	best_candidate = max(candidates, key = lambda x: x[2])
	(ba_dec, _, _) = best_candidate
	return ba_dec.decode("utf-8")

if __name__ == "__main__":
	print c4('./4.txt')
