from mcc_helpers import generate_aes_key, pkcs7_pad, pkcs7_strip, \
						encrypt_aes_ecb, decrypt_aes_ecb

def c13():
	oracle = ProfileOracle()

	#Obtain an encrypted block which begins with 'admin'
	this_input = 2 * 'A' + '@abc.com' + 'admin'
	ct = oracle.enc_profile_for(this_input)
	admin_block = ct[16:32]

	#Obtain 3 encrypted blocks (ie. 48 bytes) consisting of 48 copies of the
	#char '0' (dec 48) (used for pkcs7 padding)
	this_input = 2 * 'A' + '@abc.com' + 48 * '0' 
	ct = oracle.enc_profile_for(this_input)
	padding_block = ct[16:64]

	#Obtain a ciphertext with a block boundary between 'role=' and 'user'
	this_input = 5 * 'A' + '@abc.com'
	ct = oracle.enc_profile_for(this_input)

	#Remove block beginning with 'user', replace with block beginning with
	#'admin', and append pkcs7 padding
	ct = ct[0:32] + admin_block + padding_block

	profile = oracle.decrypt_profile(ct)
	return profile

def kv_parse(input):
	kvs = [x.split('=') for x in input.split('&')]
	result = {}
	for kv in kvs:
		if len(kv) == 2:
			result[kv[0]] = kv[1]
	return result

def profile_for(email):
	email.replace('&', '')
	email.replace('=', '')

	profile = []
	profile.append(('email',email))
	profile.append(('uid',10))
	profile.append(('role','user'))

	encoded_profile = '&'.join([k + '=' + str(v) for (k,v) in profile])
	return encoded_profile

class ProfileOracle:
	def __init__(self):
		self._key = generate_aes_key()

	#A. Encrypt the encoded user profile under the key
	def enc_profile_for(self, email):
		encoded_profile = profile_for(email)
		pt = pkcs7_pad(encoded_profile, 16)
		encrypted_profile = encrypt_aes_ecb(pt, self._key)
		return encrypted_profile

	#B. Decrypt the encoded user profile and parse it
	def decrypt_profile(self, encrypted_profile):
		pt = decrypt_aes_ecb(encrypted_profile, self._key)
		encoded_profile = pkcs7_strip(pt)
		profile = kv_parse(encoded_profile)
		return profile
		
if __name__ == "__main__":
	print c13()
