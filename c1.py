def hex_string_to_b64_string(hex_string):

	b64_index = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	#Pad hex string to multiple of 3 chars = 12 bits (= lcm(4,6))
	padding_length = -len(hex_string) % 3
	hex_string = padding_length * '0' + hex_string

	hex_int_list = [hex_char_to_int(x) for x in hex_string]
	b64_int_list = []
	#Convert hex to b64 in 12 bit chunks	
	for i in range(0,len(hex_int_list)/3):
		h2 = hex_int_list[3*i]
		h1 = hex_int_list[3*i+1]
		h0 = hex_int_list[3*i+2]
		b1 = (h2 << 2) + (h1 >> 2)
		b0 = ((h1 << 4) + h0) & 63
		b64_int_list.append(b1)
		b64_int_list.append(b0)

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
