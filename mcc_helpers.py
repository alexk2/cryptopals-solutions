def hex_string_to_bytearray(hex_string):
	
	#Pad hex string to multiple of 2 chars = 8 bits
	padding_length = -len(hex_string) % 2
	hex_string = padding_length * '0' + hex_string

	hex_int_list = [hex_char_to_int(x) for x in hex_string]
	this_bytearray = bytearray()
	#Convert hex digits to bytes in 2 hex digit chunks
	for i in range(0, len(hex_int_list)/2):
		h = hex_int_list[2*i:2*i+2]
		b = (h[0] << 4) + h[1]
		this_bytearray.append(b)

	return this_bytearray

def bytearray_to_b64_string(this_bytearray):

	b64_index = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	#Pad bytearray to multiple of 3 bytes = 24 bits (= lcm(8,6))
	padding_length = -len(this_bytearray) % 3
	this_bytearray = padding_length * '\0' + this_bytearray

	b64_int_list = []
	b64 = 4 * [0]
	#Convert bytes to b64 digits in 3 byte chunks	
	for i in range(0, len(this_bytearray)/3):
		b = this_bytearray[3*i:3*i+3]
		b64[0] = b[0] >> 2
		b64[1] = ((b[0] << 4) + (b[1] >> 4)) & 63
		b64[2] = ((b[1] << 2) + (b[2] >> 6)) & 63
		b64[3] = b[2] & 63
		b64_int_list.extend(b64)

	b64_string = ''.join([b64_index[x] for x in b64_int_list])
	return b64_string

def hex_char_to_int(hex_char):
	if '0' <= hex_char and hex_char <= '9':
		return ord(hex_char) - ord('0')
	if 'a' <= hex_char and hex_char <= 'f':
		return 10 + ord(hex_char) - ord('a')
	if 'A' <= hex_char and hex_char <= 'F':
		return 10 + ord(hex_char) - ord('A')
	raise Exception("Invalid input")
