from mcc_helpers import generate_aes_key, random_bytes, pkcs7_pad, \
						pkcs7_strip, encrypt_aes_cbc, decrypt_aes_cbc
import urllib

def c16():

	target = CBCBitFlipTarget()
	ct = target.encrypt('')
	return target.check_admin(ct)

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

	def check_admin(self, ct):
		pt = pkcs7_strip(decrypt_aes_cbc(ct, self._key, self._iv))
		kvs = [x.split('=') for x in pt.split(';')]
		kvs_dict = {x:y for (x,y) in kvs}
		if kvs_dict.has_key('admin') and kvs_dict['admin'] == 'true':
			return True
		else:
			return False

if __name__ == "__main__":
	print c16()
