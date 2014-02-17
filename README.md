Hash-Algorithm-Identifier
=========================

A python tool to identify different Hash Function Algorithms.

This is my first python tool. Its a Hash Identifier which can be used to identify the login hash or cookie hash, password hash etc. This tool can detect the algorithm used to store the password in a database in hash form, of various forums like MyBB, phpBB3, Drupal, Joomla, wordpress etc.

If you don't know what a Hash Function is then I recommend you to reading about it here :- http://en.wikipedia.org/wiki/Hash_function

Anyone who have used Kali Linux or Backtrack Linix, they may know that you have a tool named hash-identifier and the link to the source of the tool is given below :

https://code.google.com/p/hash-identifier/

But the code isn't very efficient and has a huge if-else-if and method construct which is repetitive and this makes the code redundant.

Here's my version of HashIdentifier. (# of lines of code : 116)

### Screenshot

![hash-identifier](http://i.imgur.com/zQvuSH2.png?1)


The style nd design of the code has been kept same as the original hash-identifier in the Google-code project link given above.

### How to Use ?

To use this simply run (The app will start):-

`python HashIdentifier.py`

To make it executable as well run :-

`chmod +x HashIdentifier.py`

and then starting it by executing (One's the executable is made you can start it by typing the following text only):- 


`./HashIdentifier.py`


If you don't understand the steps above then don't worry. In the github repository posted you will find a file named start.sh, just execute it and it will start running.

To execute the start.sh, type the following in the terminal :- 

`sh start.sh`

### About the Code

As it is evident from the code that I have used regular expressions to identify the hashes. The hashes are being identified because they have certain characteristics and when matched properly they will give give the correct results. Using regular expressions to identify the hash makes the code neat and easy to understand only if you have a proper understanding of them. 

To understand the regex expressions used in the code, [VISIT THIS SITE] (http://regex101.com/) and paste the Regex Expression in its proper place and thereby you get the explanation.

#### Specifications :- 

**Encryption formats supported** :- 78 Hashes (Listed below)


* Blowfish(Eggdrop)
* Blowfish(OpenBSD)
* DES(Unix)
* MD5(Unix)
* MD5(APR)
* MD5(MyBB)
* MD5(Joomla)
* MD5(Wordpress)
* MD5(phpBB3)
* MD5(Cisco PIX)
* MD5(osCommerce)
* MD5(Palshop)
* Lineage II C4
* RIPEMD-320
* RIPEMD-320(HMAC)
* SHA-1(Django)
* SHA-512(Drupal)
* SHA-256(Django)
* SHA-384(Django)
* SHA-256(Unix)
* SHA-512(Unix)
* SHA-384
* SHA-512
* SSHA-1
* MySQL 5.x
* MySQL3.x
* LM
* SAM(LM_Hash:NT_Hash)
* MSSQL(2000)
* MSSQL(2005)
* MSSQL(2008)
* HAVAL-160
* TIGER-160
* TIGER-160(HMAC)
* SHA-1
* RIPEMD-160
* RIPEMD-160(HMAC)
* SHA-1(MaNGOS)
* SHA-1(MaNGOS2)
* MySQL 4.x
* HAVAL-256
* SHA-256
* GOST R 34.11-94
* Snefru-256
* RIPEMD-256
* RipeMD-256(HMAC)
* HAVAL-192
* Tiger-192
* TIGER-192(HMAC)
* HAVAL-224
* SHA-224
* SHA-224(HMAC)
* Adler32
* CRC-32
* CRC-32B
* GHash-32-3
* GHash-32-5
* XOR-32
* CRC-16-CCITT
* CRC-16
* FCS-16
* Tiger-128
* Tiger-128(HMAC)
* NTLM
* Domain Cached Credentials(DCC)
* Domain Cached Credentials 2(DCC2)
* RAdmin v2.x
* MD4
* MD2
* MD5(HMAC(Wordpress))
* MD5(HMAC)
* MD5
* Snefru-128
* Snefru-128(HMAC)
* RIPEMD-128
* RIPEMD-128(HMAC)
* HAVAL-128
* HAVAL-128(HMAC)

#### No. of Hashes it can Identify : 78


This Tool will be updated soon to support several other Hashes. Suggestion and feedback are welcome.


