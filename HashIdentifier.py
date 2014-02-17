#!/usr/bin/env python
#encoding: utf-8
#@author: Psycho_Coder <https://psychocoder.github.io/>                            

import re

TITLE = '''
 _     _            _        _____    _                  _  ___ _             
| |   | |          | |      (_____)  | |            _   (_)/ __|_)            
| |__ | | ____  ___| | _       _   _ | | ____ ____ | |_  _| |__ _  ____  ____ 
|  __)| |/ _  |/___) || \     | | / || |/ _  )  _ \|  _)| |  __) |/ _  )/ ___)
| |   | ( ( | |___ | | | |   _| |( (_| ( (/ /| | | | |__| | |  | ( (/ /| |    
|_|   |_|\_||_(___/|_| |_|  (_____)____|\____)_| |_|\___)_|_|  |_|\____)_|    
_______________________________________________________________________________

						   Version: 1.0 by Psycho_Coder
						   at HackCommunity.com.
_______________________________________________________________________________
	'''

USAGE = '''
		Usage: 

		In the terminal run : python HashIdentifier.py

		Tested with python 2.7.
	
	'''

HASHES = (
		("Blowfish(Eggdrop)",	"^\+[a-z0-9\/\.]{12}$"),
		("Blowfish(OpenBSD)",	"^\$2a\$[0-9]{0,2}?\$[a-z0-9\/\.]{53}$"), 	
		("DES(Unix)",		"^.{0,2}[a-z0-9\/\.]{11}$"),
		("MD5(Unix)",		"^\$1\$.{0,8}\$[a-z0-9\/\.]{22}$"),
		("MD5(APR)",		"^\$apr1\$.{0,8}\$[a-z0-9\/\.]{22}$"),
		("MD5(MyBB)",		"^[a-f-0-9]{32}:[a-z0-9]{8}$"),
		("MD5(Joomla)",		"^[a-f0-9]{32}:[a-z0-9]{16,32}$"),
		("MD5(Wordpress)",	"^\$P\$[a-z0-9\/\.]{31}$"),
		("MD5(phpBB3)",		"^\$H\$[A-Fa-z0-9\/\.]{31}$"),
		("MD5(Cisco PIX)",	"^[a-z0-9\/\.]{16}$"),
		("MD5(osCommerce)",	"^[a-f0-9]{32}:[a-z0-9]{2}$"),
		("MD5(Palshop)",	"^[a-f0-9]{51}$"),
		("Lineage II C4",	"^0x[a-f0-9]{32}$"),
		(("RIPEMD-320","RIPEMD-320(HMAC)"),		"^[a-f0-9]{80}$"),
		("SHA-1(Django)",	"^sha1\$.{0,32}\$[a-f0-9]{40}$"),
		("SHA-512(Drupal)",	"^\$S\$[a-z0-9\/\.]{52}$"),
		("SHA-256(Django)",	"^sha256\$.{0,32}\$[a-f0-9]{64}$"),
		("SHA-384(Django)",	"^sha384\$.{0,32}\$[a-f0-9]{96}$"),
		("SHA-256(Unix)",	"^\$5\$.{0,22}\$[a-z0-9\/\.]{43,69}$"),
		("SHA-512(Unix)",	"^\$6\$.{0,22}\$[a-z0-9\/\.]{86}$"),
		("SHA-384",		"^[a-f0-9]{96}$"),
		("SHA-512","Whirlpool",	"^[a-f0-9]{128}$"),
		("SSHA-1",		"^({SSHA})?[a-z0-9\+\/]{32,38}?(==)?$"),
		("MySQL 5.x",		"^\*[a-f0-9]{40}$"),
		(("MySQL3.x","LM"), 	"^[a-f0-9]{16}$"),
		("SAM(LM_Hash:NT_Hash)","^[a-f-0-9]{32}:[a-f-0-9]{32}$"),
		("MSSQL(2000)",		"^0x0100[a-f0-9]{0,8}?[a-f0-9]{80}$"),
		(("MSSQL(2005)","MSSQL(2008)"),		"^0x0100[a-f0-9]{0,8}?[a-f0-9]{40}$"),				
		(("HAVAL-160","TIGER-160","TIGER-160(HMAC)","SHA-1","RIPEMD-160","RIPEMD-160(HMAC)","SHA-1(MaNGOS)","SHA-1(MaNGOS2)","MySQL 4.x"),	"^[a-f0-9]{40}$"),
		(("HAVAL-256","SHA-256","GOST R 34.11-94","Snefru-256","RIPEMD-256","RipeMD-256(HMAC)"),		"^[a-f0-9]{64}$"),
		(("HAVAL-192","Tiger-192","TIGER-192(HMAC)"),		"^[a-f0-9]{48}$"),
		(("HAVAL-224","SHA-224","SHA-224(HMAC)"),		"^[a-f0-9]{56}$"),
		(("Adler32","CRC-32","CRC-32B","GHash-32-3","GHash-32-5","XOR-32"),		"^[a-f0-9]{8}$"),
		(("CRC-16-CCITT","CRC-16","FCS-16"),		"^[a-f0-9]{4}$"),
		(("Tiger-128","Tiger-128(HMAC)","NTLM","Domain Cached Credentials(DCC)","Domain Cached Credentials 2(DCC2)","RAdmin v2.x","MD4","MD2","MD5(HMAC(Wordpress))","MD5(HMAC)","MD5","Snefru-128","Snefru-128(HMAC)","RIPEMD-128","RIPEMD-128(HMAC)","HAVAL-128","HAVAL-128(HMAC)"),		"^[0-9a-f]{32}$"),	
)

# Function to identify all the hashes and return the results as list.
def identifyHashes(inputHash):
	
	# List to store the names of the identified Hash Algorithms
	res = []
	
	# Loop through all the hashes in the HASHES tuple and find all the possible hashes.
	for items in HASHES:
        	if (re.match(items[1],inputHash,re.IGNORECASE)):
	    		res += [items[0]] if ( type(items[0]) is str ) else items[0]	
    	return res
	
print TITLE
print USAGE

# Run infinite loop to ask for entering a hash everytime a hash if found.
while(1):
	print ("_" * 80)
	print "\n"
	
	# Take the Hash as Input from the User.
	inputHash = raw_input("Enter the Hash : ");
	
	if (len(inputHash) < 1):	
		print ("\nPlease enter the hash. No input hash found.")		
	else:	
		# trim the hash entered and remove the unwanted spaces
		inputHash = inputHash.strip()
				
		# Do the operation of Identifying the hashes.
		results = identifyHashes(inputHash)

		# If the length of the list returned by the hash identifying method is zero 
		# that means no hashes algorithms have been found 
		if (len(results) == 0):
			print ("\n\nNot a Hash or Hash Unknown")	
		elif (len(results) > 2):
			
			# Show the results with most and less probable hash algorithms
			print ("\nMost Probable Hash Algorithms found:\n")
			print "[+] " + results[0]
			print "[+] " + results[1]
			print ("\nOther less Probable Hash Algorithms found:\n")
			for item in range(int(len(results))-2):
				print "[+] " + results[item+2]
		else:
			print ("\nMost Probable Hash Algorithms found:\n")
			for item in range(int(len(results))):
				print "[+] " + results[item]
