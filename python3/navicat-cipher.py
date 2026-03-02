#!/usr/bin/env python3
import io
import os
import struct
import argparse

from cryptography.hazmat.primitives.hashes import Hash, SHA1
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish
from cryptography.hazmat.primitives.ciphers.modes import ECB, CBC, GCM
from cryptography.hazmat.primitives.padding import PKCS7

def align_down(x: int, alignment: int) -> int:
    return (x // alignment) * alignment

def align_up(x: int, alignment: int) -> int:
    return align_down(x + (alignment - 1), alignment)

def xor_bytes(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b)
    return bytes(i ^ j for i, j in zip(a, b))

def fetch_navicat_cred() -> bytes:
    import win32cred
    return bytes.fromhex(win32cred.CredRead('navicat_cred', win32cred.CRED_TYPE_GENERIC)['CredentialBlob'].decode('ascii'))

def derive_v3_key_from_navicat_cred(data: bytes) -> bytes:
    TABLE = bytes(i + 1 for i in range(32))
    aes256_key = bytearray(data)
    aes256_key[25:25 + 4] = map(lambda i: TABLE[i], (2, 0, 2, 5))
    return bytes(aes256_key)

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

class NavicatCryptoV3:
    def __init__(self, key: bytes):
        self._key = bytes(key)

    def _pad(self, data: bytes):
        blocksize = AES.block_size // 8

        content_length = len(data)
        total_length = align_up(2 + content_length, blocksize)
        padding_length = total_length - (2 + content_length)

        return struct.pack('<H{:d}s{:d}s'.format(content_length, padding_length), content_length, data, os.urandom(padding_length))

    def _unpad(self, data: bytes):
        blocksize = AES.block_size // 8

        content_length, = struct.unpack('<H', data[:2])
        total_length = align_up(2 + content_length, blocksize)
        padding_length = total_length - (2 + content_length)

        content, _ = struct.unpack('{:d}s{:d}s'.format(content_length, padding_length), data[2:])
        return content

    def encrypt_string(self, s: str) -> str:
        plaintext = s.encode('ascii')

        nonce = os.urandom(12)

        cipher = Cipher(AES(self._key), GCM(nonce))
        encryptor = cipher.encryptor()

        with io.BytesIO() as buf:
            buf.write(nonce)
            buf.write(encryptor.update(self._pad(plaintext)))
            buf.write(encryptor.finalize())
            buf.write(encryptor.tag)
            return buf.getvalue().hex().upper()

    def decrypt_string(self, s: str) -> str:
        data = bytes.fromhex(s)
        nonce, ciphertext, tag = struct.unpack('12s{:d}s16s'.format(len(data) - 12 - 16), data)

        cipher = Cipher(AES(self._key), GCM(nonce, tag))
        decryptor = cipher.decryptor()

        with io.BytesIO() as buf:
            buf.write(decryptor.update(ciphertext))
            buf.write(decryptor.finalize())
            return self._unpad(buf.getvalue()).decode('ascii')

def main():
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest = 'operation', required = True)

    enc_subparser = subparsers.add_parser('enc', help = 'do encrypt operation')
    group = enc_subparser.add_mutually_exclusive_group(required = True)
    group.add_argument('-v1', action = 'store_true', help = 'use v1 algorithm')
    group.add_argument('-v2', action = 'store_true', help = 'use v2 algorithm')
    group.add_argument('-v3', action = 'store_true', help = 'use v3 algorithm')
    enc_subparser.add_argument('--cred', help = 'the value of navicat_cred, which is used by -v3', type = lambda s: bytes.fromhex(s), default = argparse.SUPPRESS)
    enc_subparser.add_argument('PASSWD', help = 'the password in plaintext')

    dec_subparser = subparsers.add_parser('dec', help = 'do decrypt operation')
    group = dec_subparser.add_mutually_exclusive_group(required = True)
    group.add_argument('-v1', action = 'store_true', help = 'use v1 algorithm')
    group.add_argument('-v2', action = 'store_true', help = 'use v2 algorithm')
    group.add_argument('-v3', action = 'store_true', help = 'use v3 algorithm')
    dec_subparser.add_argument('--cred', help = 'the value of navicat_cred, which is used by -v3', type = lambda s: bytes.fromhex(s), default = argparse.SUPPRESS)
    dec_subparser.add_argument('PASSWD', help = 'the password in ciphertext')

    args = parser.parse_args()

    if args.operation == 'enc':
        if args.v1:
            print(NavicatCryptoV1().encrypt_string(args.PASSWD))
        elif args.v2:
            print(NavicatCryptoV2().encrypt_string(args.PASSWD))
        elif args.v3:
            if hasattr(args, 'cred'):
                navicat_cred = bytearray(args.cred)
            else:
                navicat_cred = fetch_navicat_cred()
            print(NavicatCryptoV3(derive_v3_key_from_navicat_cred(navicat_cred)).encrypt_string(args.PASSWD))
        else:
            raise NotImplementedError()
    elif args.operation == 'dec':
        if args.v1:
            print(NavicatCryptoV1().decrypt_string(args.PASSWD))
        elif args.v2:
            print(NavicatCryptoV2().decrypt_string(args.PASSWD))
        elif args.v3:
            if hasattr(args, 'cred'):
                navicat_cred = bytearray(args.cred)
            else:
                navicat_cred = fetch_navicat_cred()
            print(NavicatCryptoV3(derive_v3_key_from_navicat_cred(navicat_cred)).decrypt_string(args.PASSWD))
        else:
            raise NotImplementedError()
    else:
        raise NotImplementedError()

if __name__ == '__main__':
    main()
