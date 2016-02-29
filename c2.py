from mcc_helpers import hex_string_to_bytearray
from mcc_helpers import bytearray_to_hex_string
from mcc_helpers import bytearray_xor

def c2(s1, s2):
	ba1 = hex_string_to_bytearray(s1)
	ba2 = hex_string_to_bytearray(s2)

	ba_xor = bytearray_xor(ba1,ba2)

	return bytearray_to_hex_string(ba_xor) 

if __name__ == "__main__":
	s1 = "1c0111001f010100061a024b53535009181c"
	s2 = "686974207468652062756c6c277320657965"
	print c2(s1, s2)
