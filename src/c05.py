from cryptopals import bytearray_to_hex_string
from cryptopals import encrypt_rk_xor

def c5(plaintext, key):
	plaintext_ba = bytearray(plaintext)
	key_ba = bytearray(key)
	ba_enc = encrypt_rk_xor(plaintext_ba, key_ba)
	hs_enc = bytearray_to_hex_string(ba_enc)
	return hs_enc

if __name__ == "__main__":
	plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key = "ICE"
	print c5(plaintext, key)
