#!/usr/bin/env python
"""
Usage: tibudecrypt.py [-v] <file>
       tibudecrypt.py [-v] <file> [<password>]
       tibudecrypt.py --version
       tibudecrypt.py -h | --help

Arguments:
    <file>          File to decrypt.
    <password>      Password to use to decrypt file.

Options:
    -v --verbose    Enable verbose output.
    --version       Show program version.

"""

from __future__ import print_function
from __future__ import unicode_literals

#"""
# File Format
# Information taken from Christian Egger's G+ page.
# https://plus.google.com/101760059763010172705/posts/MQBmYhKDex5
#=====
# "TB_ARMOR_V1" '\\n'
# pass_hmac_key '\\n'
# pass_hmac_result '\\n'
# public_key '\\n'
# enc_privkey_spec '\\n'
# enc_sesskey_spec '\\n'
# Data
#=====
# Each of the 5 "variables" (pass_hmac_key, pass_hmac_result,
# public_key, enc_privkey_spec, enc_sesskey_spec) is stored in
# Base64 format without linewraps (of course) and can be decoded with:
# Base64.decode( pass_hmac_key, Base64.NO_WRAP)
#
# Then the user-supplied passphrase (String) can be verified as follows:
# Mac mac = Mac.getInstance("HmacSHA1");
# mac.init(new SecretKeySpec(pass_hmac_key, "HmacSHA1"));
# byte[] sigBytes = mac.doFinal(passphrase.getBytes("UTF-8"));
# boolean passphraseMatches = Arrays.equals(sigBytes, pass_hmac_result);
#
# Then the passphrase is independently hashed with SHA-1. We append 0x00 bytes
# to the 160-bit result to constitute the 256-bit AES key which is used to
# decrypt "enc_privkey_spec" (with an IV of 0x00 bytes).
#
#Then we build the KeyPair object as follows:
# KeyFactory keyFactory = KeyFactory.getInstance("RSA");
# PrivateKey privateKey2 = keyFactory.generatePrivate(
#   new PKCS8EncodedKeySpec(privateKey));
# PublicKey public_key2 = keyFactory.generatePublic(
#   new X509EncodedKeySpec(public_key));
# KeyPair keyPair = new KeyPair(public_key2, privateKey2);
#
#Then we decrypt the session key as follows:
# Cipher rsaDecrypt = Cipher.getInstance("RSA/NONE/PKCS1Padding");
# rsaDecrypt.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
# ByteArrayOutputStream baos = new ByteArrayOutputStream();
# CipherOutputStream cos = new CipherOutputStream(baos, rsaDecrypt);
# cos.write(enc_sesskey_spec); cos.close();
# byte[] sessionKey = baos.toByteArray();
#
# And finally, we decrypt the data itself with the session key (which can be
# either a 128-bit, 192-bit or 256-bit key) and with a 0x00 IV.
#
# While the "zero" IV is suboptimal from a security standpoint, it allows
# files to be encoded faster - because every little bit counts, especially
# when we store backups with LZO compression.
#
# Use:
# As of 2013/03/04 this script requires the pkcs8 branch of
# https://github.com/Legrandin/pycrypto in order to run correctly.
# Standard PyCrypto does not yet support PKCS#8
#
# ./tibudecrypt.py filename
#"""

import os
import sys
import base64
import getpass
import hashlib
import hmac
import docopt
import six
import Crypto.Cipher.AES
import Crypto.Cipher.PKCS1_v1_5
import Crypto.PublicKey.RSA

TIBU_IV = chr(0x00) * 16
TB_VALID_HEADER = 'TB_ARMOR_V1'
VERSION = '0.1'


def pkcs5_unpad(chunk):
    """Return data after PKCS5 unpadding
    With python3 bytes are already treated as arrays of ints so
    we don't have to convert them with ord.
    """
    if not six.PY3:
        padding_length = ord(chunk[-1])
    else:
        padding_length = chunk[-1]

    # cite https://stackoverflow.com/a/20457519
    if padding_length < 1 or padding_length > Crypto.Cipher.AES.block_size:
        raise ValueError("bad decrypt pad (%d)" % padding_length)
    # all the pad-bytes must be the same
    if chunk[-padding_length:] != (padding_length * chr(padding_length)):
        # this is similar to the bad decrypt:evp_enc.c from openssl program
        raise ValueError("bad decrypt")
    return chunk[:-padding_length]


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


class TiBUFile(object):
    """
    Class for performing decryption on Titanium Backup encrypted files.
    """
    def __init__(self, filename):
        self.filename = filename
        self.pass_hmac_key = None
        self.pass_hmac_result = None
        self.enc_privkey_spec = None
        self.enc_sesskey_spec = None
        self.encrypted_data_start_byte_offset = None
        self.hashed_pass = None
        self.cipher = None
        self.check_header()
        self.read_file()

    def check_header(self):
        """
        Checks that the file header matches the Titanium Armor header
        raises the InvalidHeader exception if there is no match.
        """
        header_len = len(TB_VALID_HEADER)
        with open(self.filename, 'rb') as in_file:
            data = in_file.read(header_len).decode('utf-8')

        if not (len(data) == header_len
                and data == TB_VALID_HEADER):
            raise InvalidHeader('Invalid header')

    def check_password(self, password):
        """
        Performs HMAC password verification and hashes the password
        for use when decrypting the private key and session key.
        """
        mac = hmac.new(
            self.pass_hmac_key,
            password,
            hashlib.sha1)
        if mac.digest() == self.pass_hmac_result:
            sha1 = hashlib.sha1()
            sha1.update(password)
            self.hashed_pass = sha1.digest().ljust(
                32, chr(0x00).encode('ascii'))
        else:
            raise PasswordMismatchError('Password Mismatch')
        self.setup_crypto()

    def read_file(self):
        """
        Reads the encrypted file and splits out the 7 sections that
        we're interested in.
        """
        try:
            with open(self.filename, 'rb') as in_file:
                in_file.readline()  # skip the header
                pass_hmac_key = in_file.readline()
                pass_hmac_result = in_file.readline()
                in_file.readline()  # dummy public key
                enc_privkey_spec = in_file.readline()
                enc_sesskey_spec = in_file.readline()

                self.encrypted_data_start_byte_offset = in_file.tell()
                in_file.close()

            self.pass_hmac_key = base64.b64decode(pass_hmac_key)
            self.pass_hmac_result = base64.b64decode(pass_hmac_result)
            self.enc_privkey_spec = base64.b64decode(enc_privkey_spec)
            self.enc_sesskey_spec = base64.b64decode(enc_sesskey_spec)
        except:
            raise

    def setup_crypto(self):
        cipher = Crypto.Cipher.AES.new(
            self.hashed_pass,
            mode=Crypto.Cipher.AES.MODE_CBC,
            IV=TIBU_IV)

        dec_privkey_spec = pkcs5_unpad(cipher.decrypt(self.enc_privkey_spec))

        rsa_privkey = Crypto.PublicKey.RSA.importKey(
            dec_privkey_spec)
        cipher = Crypto.Cipher.PKCS1_v1_5.new(rsa_privkey)
        dec_sesskey = cipher.decrypt(
            self.enc_sesskey_spec,
            None)

        self.cipher = Crypto.Cipher.AES.new(
            dec_sesskey,
            mode=Crypto.Cipher.AES.MODE_CBC,
            IV=TIBU_IV)


def main(args):
    """Main"""
    try:
        filename = args.get('<file>')
    except NameError:
        return "Supply a file to decrypt."

    try:
        encrypted_file = TiBUFile(filename)
    except InvalidHeader as exc:
        return "Not a Titanium Backup encrypted file: {e}".format(e=exc)
    except IOError as exc:
        return "Error. {e}".format(e=exc)

    try:
        password = args.get('<password>')
        if password is None:
            password = getpass.getpass()
        encrypted_file.check_password(password.encode('utf-8'))
    except PasswordMismatchError as exc:
        return "Error: {e}".format(e=exc)

    try:
        decrypted_filename = "decrypted-{filename}".format(
            filename=os.path.basename(filename))

        with open(encrypted_file.filename, 'rb') as in_file, open(decrypted_filename, 'wb') as out_file:
            next_chunk = ''
            finished = False
            in_file.seek(encrypted_file.encrypted_data_start_byte_offset, 0)
            while not finished:
                chunk, next_chunk = next_chunk, encrypted_file.cipher.decrypt(in_file.read(1024 * Crypto.Cipher.AES.block_size))

                # ensure last chunk is padded correctly
                if len(next_chunk) == 0:
                    chunk = pkcs5_unpad(chunk)
                    finished = True

                out_file.write(chunk)

    except IOError as exc:
        return "Error while writing decrypted data: {e}".format(
            e=exc.strerror)

    print("Success. Decrypted file '{decrypted_filename}' written.".format(
        decrypted_filename=decrypted_filename))

    print("consider now running the following to verify the decrypted file WITHOUT writing bytes to disk:\n")
    print("gunzip --stdout '{decrypted_filename}' | tar tf - >/dev/null; [[ 0 == $? ]] && echo 'gunzip and tar test successful' || echo 'there was an error testing the decrypted archive'".format(decrypted_filename=decrypted_filename))
    print("\nit will test the gzip archive, e.g. for corruption or any garbage bytes, and then test the tar for errors.")


if __name__ == '__main__':
    ARGS = docopt.docopt(__doc__, version=VERSION)
    sys.exit(main(ARGS))
