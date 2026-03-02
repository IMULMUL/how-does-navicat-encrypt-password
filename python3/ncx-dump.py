#!/usr/bin/env python3
import io, sys
import pathlib
import xml.etree.ElementTree

import argparse
import configparser

from cryptography.hazmat.primitives.hashes import Hash, SHA1
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish
from cryptography.hazmat.primitives.ciphers.modes import ECB, CBC
from cryptography.hazmat.primitives.padding import PKCS7

def xor_bytes(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b)
    return bytes(i ^ j for i, j in zip(a, b))

class NavicatCryptoV1:
    def __init__(self):
        sha1 = Hash(SHA1())
        sha1.update(b'3DC5CA39')
        self._key = sha1.finalize()

        self._cipher = Cipher(Blowfish(self._key), ECB())
        self._ecb_encryptor = self._cipher.encryptor()
        self._ecb_decryptor = self._cipher.decryptor()

        with io.BytesIO() as buf:
            buf.write(self._ecb_encryptor.update(b'\xff\xff\xff\xff\xff\xff\xff\xff'))
            self._initial_vector = buf.getvalue()
            assert len(self._initial_vector) == Blowfish.block_size // 8
    
    def encrypt_string(self, s: str) -> str:
        blocksize = Blowfish.block_size // 8
        current_vector = self._initial_vector

        plaintext = s.encode('ascii')
        rounds, leftover = divmod(len(plaintext), blocksize)

        with io.BytesIO() as ciphertext_buf:
            for off in range(0, rounds * blocksize, blocksize):
                t = xor_bytes(plaintext[off:off + blocksize], current_vector)
                
                t = self._ecb_encryptor.update(t)
                assert len(t) == blocksize

                current_vector = xor_bytes(current_vector, t)
                ciphertext_buf.write(t)

            if leftover > 0:
                current_vector = self._ecb_encryptor.update(current_vector)
                ciphertext_buf.write(xor_bytes(plaintext[rounds * blocksize:], current_vector[:leftover]))

            return ciphertext_buf.getvalue().hex().upper()
                
    def decrypt_string(self, s: str) -> str:
        blocksize = Blowfish.block_size // 8
        current_vector = self._initial_vector

        ciphertext = bytes.fromhex(s)
        rounds, leftover = divmod(len(ciphertext), blocksize)

        with io.BytesIO() as plaintext_buf:
            for off in range(0, rounds * blocksize, blocksize):
                t = self._ecb_decryptor.update(ciphertext[off:off + blocksize])
                assert len(t) == blocksize

                t = xor_bytes(t, current_vector)
                current_vector = xor_bytes(current_vector, ciphertext[off:off + blocksize])

                plaintext_buf.write(t)

            if leftover > 0:
                current_vector = self._ecb_encryptor.update(current_vector)
                plaintext_buf.write(xor_bytes(ciphertext[rounds * blocksize:], current_vector[:leftover]))

            return plaintext_buf.getvalue().decode('ascii')

class NavicatCryptoV2:
    def __init__(self):
        self._key = b'libcckeylibcckey'
        self._initial_vector = b'libcciv libcciv '

    def encrypt_string(self, s: str) -> str:
        plaintext = s.encode('ascii')

        cipher = Cipher(AES(self._key), CBC(self._initial_vector))
        encryptor = cipher.encryptor()

        padding = PKCS7(AES.block_size)
        padder = padding.padder()

        with io.BytesIO() as buf:
            buf.write(padder.update(plaintext))
            buf.write(padder.finalize())
            padded_plaintext = buf.getvalue()

        with io.BytesIO() as buf:
            buf.write(encryptor.update(padded_plaintext))
            buf.write(encryptor.finalize())
            return buf.getvalue().hex().upper()

    def decrypt_string(self, s: str) -> str:
        ciphertext = bytes.fromhex(s)

        cipher = Cipher(AES(self._key), CBC(self._initial_vector))
        decryptor = cipher.decryptor()

        padding = PKCS7(AES.block_size)
        unpadder = padding.unpadder()

        with io.BytesIO() as buf:
            buf.write(decryptor.update(ciphertext))
            buf.write(decryptor.finalize())
            padded_plaintext = buf.getvalue()

        with io.BytesIO() as buf:
            buf.write(unpadder.update(padded_plaintext))
            buf.write(unpadder.finalize())
            return buf.getvalue().decode('ascii')

# NavicatCryptoV3 is not needed
# because it is machine-dependent, while .ncx file is not

def decrypt_string(s: str, *ciphers) -> str:
    for cipher in ciphers:
        try:
            return cipher.decrypt_string(s)
        except:
            continue
    else:
        return '<![FAILED TO DECRYPT]!>'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('FILE', type = lambda s: pathlib.Path(s), help = 'path to .ncx file')

    args = parser.parse_args()

    with open(args.FILE, 'r') as f:
        config_xml = xml.etree.ElementTree.parse(f)
        config_ini = configparser.ConfigParser()

        cipher_v1 = NavicatCryptoV1()
        cipher_v2 = NavicatCryptoV2()

        for connection in config_xml.getroot():
            assert connection.tag == 'Connection'

            identifier = '{:s}:{:s}'.format(connection.attrib['ConnType'], connection.attrib['ConnectionName'])
            config_ini.add_section(identifier)

            if connection.attrib['ConnType'].upper() == 'SQLITE':
                config_ini.set(identifier, 'file', connection.attrib['DatabaseFileName'])
            else:
                config_ini.set(identifier, 'host', connection.attrib['Host'])
                config_ini.set(identifier, 'port', connection.attrib['Port'])

            if connection.attrib['ConnType'].upper() == 'ORACLE':
                config_ini.set(identifier, 'database', connection.attrib['Database'])

            config_ini.set(identifier, 'username', connection.attrib['UserName'])
            config_ini.set(identifier, 'password', decrypt_string(connection.attrib['Password'], cipher_v1, cipher_v2))

            if 'SSH' in connection.attrib and connection.attrib['SSH'].lower() != 'false':
                config_ini.set(identifier, 'ssh-host', connection.attrib['SSH_Host'])
                config_ini.set(identifier, 'ssh-port', connection.attrib['SSH_Port'])
                config_ini.set(identifier, 'ssh-username', connection.attrib['SSH_UserName'])
                config_ini.set(identifier, 'ssh-password', decrypt_string(connection.attrib['SSH_Password'], cipher_v1, cipher_v2))

        config_ini.write(sys.stdout)

if __name__ == '__main__':
    main()
