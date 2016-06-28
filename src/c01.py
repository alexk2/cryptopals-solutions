from cryptopals import hex_string_to_bytearray
from cryptopals import bytearray_to_b64_string

def c1(hex_string):
	this_bytearray = hex_string_to_bytearray(hex_string)
	b64_string = bytearray_to_b64_string(this_bytearray)
	return b64_string

if __name__ == "__main__":
	print c1("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
