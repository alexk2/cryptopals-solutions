from mcc_helpers import hex_string_to_bytearray

def c8(filename):

	this_file = open(filename)
	hex_strings = [x.rstrip('\n') for x in this_file.readlines()]
	bytearrays = [hex_string_to_bytearray(x) for x in hex_strings]

	#Count the number of duplicate 16 byte blocks in each ciphertext
	dup_count_list = []
	for ba in bytearrays:
		dup_count = 0
		blocks = [str(ba[i:i+16]) for i in range(0,len(ba),16)]
		unique_blocks = set(blocks)
		dup_count = len(blocks) - len(unique_blocks) 
		dup_count_list.append(dup_count)

	#Ciphertext with most duplicates is most likely to be using ECB
	max_dups = max(dup_count_list)
	ecb_ct_index = dup_count_list.index(max_dups)
	ecb_ct = bytearrays[ecb_ct_index]

	return (max_dups, ecb_ct_index, ecb_ct)

if __name__ == "__main__":
	(dups, index, ct) = c8('./8.txt')
	print "Ciphertext with index {} has {} duplicate blocks" \
		.format(index,dups)
