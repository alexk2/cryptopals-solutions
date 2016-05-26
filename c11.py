from mcc_helpers import encryption_oracle
from mcc_helpers import detect_cipher_mode

def c11():

	return detect_cipher_mode(encryption_oracle)

if __name__ == "__main__":
	(mode, detected_mode) = c11()
	print "Actual mode is " + mode
	print "Detected mode is " + detected_mode

