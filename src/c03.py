from cryptopals import hex_string_to_bytearray
from cryptopals import decrypt_sb_xor

def c3(hex_string):
	ba = hex_string_to_bytearray(hex_string)
	(ba_dec,_,_) = decrypt_sb_xor(ba)
	return ba_dec.decode("utf-8")

if __name__ == "__main__":
	print c3("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
