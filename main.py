import sys
import argparse
import hashlib
from Crypto.Cipher import AES
from getpass import getpass

def createParser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-e', '--encrypt', nargs='?', default='', type=str)
    parser.add_argument('-d', '--decrypt', nargs='?', default='', type=str)
    return parser

# ---------------- ENCRYPTING ----------------

def encrypt(name : str, password : str):	
	# read data
	with open(name, "rb") as f:		
		data = f.read()

	# key is hash of user's password    
	key = hashlib.sha256(password.encode()).digest()

	# encrypt data
	cipher = AES.new(key, AES.MODE_EAX)
	nonce = cipher.nonce
	ciphertext, tag = cipher.encrypt_and_digest(data)	

	# write encrypted data
	with open(name, "wb") as f:
		[ f.write(x) for x in (cipher.nonce, tag, ciphertext) ]

def handleEncrypt():	
	try:
		f = open(args.encrypt, "rb")			
	except: 
		print("Cannot open file " + args.encrypt)
	else:
		f.close()
		password = getpass("Enter password to encrypt: ")
		encrypt(args.encrypt, password)


# ---------------- DECRYPTING ----------------

def decrypt(name : str, password : str):
	
	file_in = open(name, 'rb')     # Open encrypted file		
	nonce = file_in.read(16)       # Read the nonce out - this is 16 bytes long
	tag = file_in.read(16)         # Read the tag out - this is 16 bytes long
	ciphered_data = file_in.read() # Read the rest of the data out
	file_in.close()                # Close file
	
	key = hashlib.sha256(password.encode()).digest() 

	# decrypt data
	try:
		cipher = AES.new(key, AES.MODE_EAX, nonce)
		plaintext = cipher.decrypt(ciphered_data)
	except ValueError: 
		# if the file is empty an error occurs
		print("File is empty or isn't encrypted. Try another file")
		return

	# write decrypted data
	try:
	    cipher.verify(tag)	    
	except ValueError:
	    print("Key incorrect. Try again")	
	else:
		with open(name, "wb") as f:
			f.write(plaintext)

def handleDecrypt():	
	try:
		f = open(args.decrypt, "rb")			
	except: 
		print("Cannot open file " + args.decrypt)
	else:
		f.close()
		password = getpass("Enter password to decrypt: ")
		decrypt(args.decrypt, password)


# ---------------- MAIN ----------------
if __name__ == "__main__":

	# аргументы
	parser = createParser()
	args = parser.parse_args(sys.argv[1:])	

	# to encrypt file
	if (args.encrypt != '') and (args.encrypt != None):
		handleEncrypt()

	# to decrypt file
	if (args.decrypt != '') and (args.decrypt != None):
		handleDecrypt()		

	# pyAesCrypt.encryptFile("data.txt", "data.txt.aes", passw)