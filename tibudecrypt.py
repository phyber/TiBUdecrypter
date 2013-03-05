#!/usr/bin/python
# File Format
# Information taken from Christian Egger's G+ page.
# https://plus.google.com/101760059763010172705/posts/MQBmYhKDex5
#=====
# "TB_ARMOR_V1" '\n'
# passHmacKey '\n'
# passHmacResult '\n'
# publicKey '\n'
# encPrivKeySpec '\n'
# encSessionKey '\n'
# Data
#=====
# Each of the 5 "variables" (passHmacKey, passHmacResult,
# publicKey, encPrivKeySpec, encSessionKey) is stored in
# Base64 format without linewraps (of course) and can be decoded with:
# Base64.decode( passHmacKey, Base64.NO_WRAP)
#
# Then the user-supplied passphrase (String) can be verified as follows:
# Mac mac = Mac.getInstance("HmacSHA1");
# mac.init(new SecretKeySpec(passHmacKey, "HmacSHA1"));
# byte[] sigBytes = mac.doFinal(passphrase.getBytes("UTF-8"));
# boolean passphraseMatches = Arrays.equals(sigBytes, passHmacResult);
#
# Then the passphrase is independently hashed with SHA-1. We append 0x00 bytes
# to the 160-bit result to constitute the 256-bit AES key which is used to
# decrypt "encPrivKeySpec" (with an IV of 0x00 bytes).
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
# cos.write(encSessionKey); cos.close();
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

class InvalidHeader(Exception):
	"""
	Raised when the header for a file doesn't match a valid
	Titanium Backup header.
	"""

class PasswordMismatchError(Exception):
	"""
	Raised when the given password is incorrect
	(hmac digest doesn't match expected digest)
	"""

class TiBUFile:
	def __init__(self, filename):
		self._VALID_HEADER = 'TB_ARMOR_V1'
		self.filename = filename
		self.check_header()
		self.read_file()

	def aes_decrypt(self, key, data):
		IV = ''.ljust(16, chr(0x00))
		dec = Crypto.Cipher.AES.new(
				key,
				mode=Crypto.Cipher.AES.MODE_CBC,
				IV=IV)
		decrypted = dec.decrypt(data)
		return self.pkcs5_unpad(decrypted)

	def check_header(self):
		headerLen = len(self._VALID_HEADER)
		with open(self.filename) as f:
			bytes = f.read(headerLen)

		if not (len(bytes) == headerLen
			and bytes == self._VALID_HEADER):
			raise InvalidHeader('Invalid header')

	def check_password(self, password):
		mac = hmac.new(
				self.filepart['passHmacKey'],
				password,
				hashlib.sha1)
		if mac.digest() == self.filepart['passHmacResult']:
			sha1 = hashlib.sha1()
			sha1.update(password)
			self.hashedPass = sha1.digest().ljust(32, chr(0x00))
		else:
			raise PasswordMismatchError('Password Mismatch')

	def decrypt(self):
		decryptedPrivateKeySpec = self.aes_decrypt(
				self.hashedPass,
				self.filepart['encPrivKeySpec'])

		rsaPrivateKey = Crypto.PublicKey.RSA.importKey(
				decryptedPrivateKeySpec)
		rsaPublicKey = Crypto.PublicKey.RSA.importKey(
				self.filepart['publicKey'])
		cipher = Crypto.Cipher.PKCS1_v1_5.new(rsaPrivateKey)
		decryptedSessionKey = cipher.decrypt(
				self.filepart['encSessionKeySpec'],
				None)
		decryptedData = self.aes_decrypt(
				decryptedSessionKey,
				self.filepart['encData'])

		return decryptedData

	def read_file(self):
		try:
			with open(self.filename, 'r') as f:
				(header, passHmacKey,
				passHmacResult, publicKey,
				encPrivKeySpec, encSessionKey,
				encData) = f.read().split('\n', 6)
		except:
			raise

		self.filepart = {
			'header': header,
			'passHmacKey': base64.b64decode(passHmacKey),
			'passHmacResult': base64.b64decode(passHmacResult),
			'publicKey': base64.b64decode(publicKey),
			'encPrivKeySpec': base64.b64decode(encPrivKeySpec),
			'encSessionKeySpec': base64.b64decode(encSessionKey),
			'encData': encData
			}

	def pkcs5_unpad(self, data):
		unpad = lambda d: d[0:-ord(d[-1])]
		return unpad(data)

def fixSysPath():
	# Search local directories first.
	index = [i for i, p in enumerate(sys.path)
			if os.path.expanduser('~') in p]
	for newindex, oldindex in enumerate(index):
		sys.path.insert(newindex, sys.path.pop(oldindex))

def main(ARGV):
	try:
		filename = ARGV[1]
	except:
		return "Supply a file to decrypt."

	try:
		encryptedFile = TiBUFile(filename)
	except InvalidHeader as e:
		return "Not a Titanium Backup encrypted file: {e}".format(e=e)
	except IOError as e:
		return "Error. {e}".format(e=e)

	try:
		password = getpass.getpass()
		encryptedFile.check_password(password)
	except PasswordMismatchError as e:
		return "Error: {e}".format(e=e)

	decryptedFile = encryptedFile.decrypt()

	try:
		decryptedFilename = "decrypted-{filename}".format(
				filename = os.path.basename(filename))
		with open(decryptedFilename, 'w') as f:
			f.write(decryptedFile)
	except IOError as e:
		return "Error while writing decrypted data: {e}".format(e=e)

	print("Success. Decrypted file '{decryptedFilename}' written.".format(
		decryptedFilename=decryptedFilename))

	return 0

if __name__ == '__main__':
	sys.exit(main(sys.argv))
