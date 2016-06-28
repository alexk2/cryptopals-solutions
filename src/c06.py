from cryptopals import b64_string_to_bytearray
from cryptopals import hamming_distance
from cryptopals import decrypt_sb_xor
from cryptopals import encrypt_rk_xor

def c6(filename):

	this_file = open(filename)
	b64_string = ''.join([x.rstrip('\n') for x in this_file.readlines()])
	this_bytearray = b64_string_to_bytearray(b64_string)

	(key, plaintext) = break_rk_xor(this_bytearray)
	return (key, plaintext)

def break_rk_xor(ciphertext):

	key_size = find_probable_key_size(ciphertext,2,40)

	#Divide ciphertext into blocks - one per key index 
	transposed_blocks = [bytearray() for x in range(0,key_size)]
	for (i,b) in enumerate(ciphertext):
		transposed_blocks[i % key_size].append(b)
	
	#Solve each block as single-byte XOR and assemble 
	#repeating-key XOR key
	rk_xor_key = bytearray()
	for block in transposed_blocks:
		(_,sb_xor_key,_) = decrypt_sb_xor(block)
		rk_xor_key.append(sb_xor_key)

	#'encrypt_rk_xor()' is self inverse - use it to decrypt
	plaintext = encrypt_rk_xor(ciphertext, rk_xor_key)
	return (rk_xor_key, plaintext)

def find_probable_key_size(ciphertext, lower, upper):

	key_size_scores = []
	for key_size in range(lower,upper):
		dist = 0
		i = 0
		#Calculate Hamming distance between each consecutive pair of
		#'key_size' bytes and add to running total
		while i+2*key_size-1 < len(ciphertext):
			first = ciphertext[i:i+key_size]
			second = ciphertext[i+key_size:i+2*key_size]
			dist += hamming_distance(first,second)
			i += 2*key_size
		if i != 0:
			#Normalize total Hamming distance by number of 
			#byte-pairs compared
			dist /= float(i/2)
			key_size_scores.append((key_size, dist))

	(probable_key_size,_) = min(key_size_scores, key = lambda x:x[1])
	return probable_key_size

if __name__ == "__main__":
	(key, plaintext) = c6('../data/6.txt')
	print "Key:\n" + key
	print "\nPlaintext:\n" + plaintext
