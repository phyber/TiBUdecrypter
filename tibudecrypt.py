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

TIBU_IV = chr(0x00).encode('ascii') * Crypto.Cipher.AES.block_size
TB_VALID_HEADER = 'TB_ARMOR_V1'
VERSION = '0.1'


def pkcs5_unpad(chunk):
    """
    Return data after PKCS5 unpadding
    With python3 bytes are already treated as arrays of ints so
    we don't have to convert them with ord.
    """
    if not six.PY3:
        padding_length = ord(chunk[-1])
    else:
        padding_length = chunk[-1]

    # Cite https://stackoverflow.com/a/20457519
    if padding_length < 1 or padding_length > Crypto.Cipher.AES.block_size:
        raise ValueError("bad decrypt pad (%d)" % padding_length)

    # all the pad-bytes must be the same
    expected_bytes = chr(padding_length).encode('ascii') * padding_length
    if chunk[-padding_length:] != expected_bytes:
        # This is similar to the bad decrypt:evp_enc.c from openssl program
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
        # Get the sha1 HMAC of the password.
        mac = hmac.new(
            self.pass_hmac_key,
            password,
            hashlib.sha1)

        # Verify that the mac that we get matches what we expect.
        if mac.digest() == self.pass_hmac_result:
            # Get the sha1 hash of the password and pad out to 32 chars with
            # 0x00.
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
                in_file.readline()  # Header, can be ignored.
                pass_hmac_key = in_file.readline()
                pass_hmac_result = in_file.readline()
                in_file.readline()  # Dummy public key, can be ignored.
                enc_privkey_spec = in_file.readline()
                enc_sesskey_spec = in_file.readline()

                self.encrypted_data_start_byte_offset = in_file.tell()
                in_file.close()

            # All of the above are base64 encoded, decode them.
            self.pass_hmac_key = base64.b64decode(pass_hmac_key)
            self.pass_hmac_result = base64.b64decode(pass_hmac_result)
            self.enc_privkey_spec = base64.b64decode(enc_privkey_spec)
            self.enc_sesskey_spec = base64.b64decode(enc_sesskey_spec)
        except:
            raise

    def setup_crypto(self):
        """
        Decrypts the various keys and gets us to the stage where we can decrypt
        the data.
        """
        # Get a cipher for decrypting the private key with the user's password.
        cipher = Crypto.Cipher.AES.new(
            self.hashed_pass,
            mode=Crypto.Cipher.AES.MODE_CBC,
            IV=TIBU_IV)

        # Decrypt the private key.
        dec_privkey_spec = pkcs5_unpad(cipher.decrypt(self.enc_privkey_spec))

        # Import the private key
        rsa_privkey = Crypto.PublicKey.RSA.importKey(dec_privkey_spec)

        # Use the private key to get a cipher for decrypting the session key.
        cipher = Crypto.Cipher.PKCS1_v1_5.new(rsa_privkey)
        dec_sesskey = cipher.decrypt(
            self.enc_sesskey_spec,
            None)

        # Finally, use the session key to get a cipher for decrypting the data.
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
            next_chunk = None
            finished = False
            in_file.seek(encrypted_file.encrypted_data_start_byte_offset, 0)

            while not finished:
                # Read and decrypt a chunk of encrypted data.
                enc_data = in_file.read(1024 * Crypto.Cipher.AES.block_size)
                chunk, next_chunk = next_chunk, encrypted_file.cipher.decrypt(enc_data)

                # On the first iteration, we won't have a chunk. Skip it.
                if chunk is None:
                    continue

                # Ensure last chunk is padded correctly
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
