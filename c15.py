from mcc_helpers import pkcs7_strip

def c15(s):

	return pkcs7_strip(s)

if __name__ == "__main__":

	sbase = "ICE ICE BABY"
	paddings = [4 * chr(4), 4 * chr(5), chr(1)+chr(2)+chr(3)+chr(4)]
	strings = [sbase + x for x in paddings]

	for s in strings:
		try:
			print repr(s) + " strips to " + c15(s)
		except Exception as e:
			print "Error: " + str(e)
