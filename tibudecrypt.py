#!/usr/bin/python
# File Format
# Information taken from Christian Egger's G+ page.
# https://plus.google.com/101760059763010172705/posts/MQBmYhKDex5
#=====
# "TB_ARMOR_V1" '\n'
# passphraseHmacKey '\n'
# passphraseHmacResult '\n'
# publicKey '\n'
# encryptedPrivateKey '\n'
# encryptedSessionKey '\n'
# Data
#=====
# Each of the 5 "variables" (passphraseHmacKey, passphraseHmacResult,
# publicKey, encryptedPrivateKey, encryptedSessionKey) is stored in
# Base64 format without linewraps (of course) and can be decoded with:
# Base64.decode( passphraseHmacKey, Base64.NO_WRAP)
#
# Then the user-supplied passphrase (String) can be verified as follows:
# Mac mac = Mac.getInstance("HmacSHA1");
# mac.init(new SecretKeySpec(passphraseHmacKey, "HmacSHA1"));
# byte[] sigBytes = mac.doFinal(passphrase.getBytes("UTF-8"));
# boolean passphraseMatches = Arrays.equals(sigBytes, passphraseHmacResult);
#
# Then the passphrase is independently hashed with SHA-1. We append 0x00 bytes
# to the 160-bit result to constitute the 256-bit AES key which is used to
# decrypt "encryptedPrivateKey" (with an IV of 0x00 bytes).
#
#Then we build the KeyPair object as follows:
# KeyFactory keyFactory = KeyFactory.getInstance("RSA");
# PrivateKey privateKey2 = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
# PublicKey publicKey2 = keyFactory.generatePublic(new X509EncodedKeySpec(publicKey));
# KeyPair keyPair = new KeyPair(publicKey2, privateKey2);
#
#Then we decrypt the session key as follows: 
# Cipher rsaDecrypt = Cipher.getInstance("RSA/NONE/PKCS1Padding");
# rsaDecrypt.init(Cipher.DECRYPT_MODE, keyPair.getPrivate()); 
# ByteArrayOutputStream baos = new ByteArrayOutputStream();
# CipherOutputStream cos = new CipherOutputStream(baos, rsaDecrypt);
# cos.write(encryptedSessionKey); cos.close();
# byte[] sessionKey = baos.toByteArray();
#
# And finally, we decrypt the data itself with the session key (which can be
# either a 128-bit, 192-bit or 256-bit key) and with a 0x00 IV.
#
# While the "zero" IV is suboptimal from a security standpoint, it allows
# files to be encoded faster - because every little bit counts, especially
# when we store backups with LZO compression.

# Use:
# As of 2013/03/04 this script requires the pkcs8 branch of
# https://github.com/Legrandin/pycrypto in order to run correctly.
# Standard PyCrypto does not yet support PKCS#8
#
# ./tibudecrypt.py filename

import os
import sys
import base64
import getpass
import hashlib
import hmac
import Crypto.Cipher.AES
import Crypto.Cipher.PKCS1_v1_5
import Crypto.PublicKey.RSA
import Crypto.Util.asn1

VALID_HEADER = 'TB_ARMOR_V1'

class InvalidHeader(Exception):
	def __init__(self, message):
		self.message = message
	def __str__(self):
		return self.message

class PasswordMismatch(Exception):
	def __init__(self, message):
		self.message = message
	def __str__(self):
		return self.message

def fixSysPath():
	# Search local directories first.
	index = [i for i, p in enumerate(sys.path) if os.path.expanduser('~') in p]
	for newindex, oldindex in enumerate(index):
		sys.path.insert(newindex, sys.path.pop(oldindex))

def checkHeader(f):
	headerLen = len(VALID_HEADER)
	bytes = f.read(headerLen)

	if len(bytes) == headerLen and bytes == VALID_HEADER:
		f.seek(0, 0)
	else:
		raise InvalidHeader('Invalid header')

def readFile(filename):
	try:
		with open(filename, 'r') as f:
			checkHeader(f)
			(header, passphraseHmacKey, passphraseHmacResult,
				publicKey, encryptedPrivateKey, encryptedSessionKey,
				data) = f.read().split('\n', 6)
	except:
		raise

	return {
			'header':		header,
			'passphraseHmacKey':	base64.b64decode(passphraseHmacKey),
			'passphraseHmacResult':	base64.b64decode(passphraseHmacResult),
			'publicKey':		base64.b64decode(publicKey),
			'encryptedPrivateKey':	base64.b64decode(encryptedPrivateKey),
			'encryptedSessionKey':	base64.b64decode(encryptedSessionKey),
			'data':			data
			}

def aesDecrypt(passphrase, data):
	IV = ''.ljust(16, chr(0x00))
	dec = Crypto.Cipher.AES.new(passphrase, mode=Crypto.Cipher.AES.MODE_CBC, IV=IV)
	decrypted = dec.decrypt(data)
	return decrypted

def checkPassword(password, fileparts):
	mac = hmac.new(fileparts.get('passphraseHmacKey'), password, hashlib.sha1)
	if mac.digest() == fileparts.get('passphraseHmacResult'):
		sha1 = hashlib.sha1()
		sha1.update(password)
		hashedPassphrase = sha1.digest().ljust(32, chr(0x00))
	else:
		raise PasswordMismatch('Password Mismatch')
		#sys.exit("Password mismatch", 1)
	
	return hashedPassphrase

def main(ARGV):
	try:
		filename = ARGV[1]
	except:
		return "Supply a file to decrypt."

	#fixSysPath()
	try:
		fileparts = readFile(filename)
	except InvalidHeader as e:
		return "{e}".format(e=e)
	except IOError as e:
		return "{e}".format(e=e)

	password = getpass.getpass()

	try:
		hashedPassphrase = checkPassword(password, fileparts)
	except PasswordMismatch as e:
		return "{e}".format(e=e)

	decryptedPrivateKeySpec = aesDecrypt(hashedPassphrase, fileparts.get('encryptedPrivateKey'))

	# we have extra bytes (TiBU padding data for some reason?), use a try block
	# for the decode.
	try:
		privateKeySpecDER = Crypto.Util.asn1.DerSequence()
		privateKeySpecDER.decode(decryptedPrivateKeySpec)
	except ValueError as e:
		pass

	rsaPrivateKey = Crypto.PublicKey.RSA.importKey(privateKeySpecDER.encode())
	rsaPublicKey = Crypto.PublicKey.RSA.importKey(fileparts.get('publicKey'))
	cipher = Crypto.Cipher.PKCS1_v1_5.new(rsaPrivateKey)
	decryptedSessionKey = cipher.decrypt(fileparts.get('encryptedSessionKey'), None)
	decryptedData = aesDecrypt(decryptedSessionKey, fileparts.get('data'))

	with open('decrypted-{filename}'.format(filename=filename), 'w') as f:
		f.write(decryptedData)

if __name__ == '__main__':
	sys.exit(main(sys.argv))
