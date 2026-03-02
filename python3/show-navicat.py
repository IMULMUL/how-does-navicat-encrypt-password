#!/usr/bin/env python3
import typing
import platform

if platform.system() != 'Windows':
    print('Please run this script on Windows!')
    exit(1)

import sys, os, io
import struct
import itertools
import configparser
import winerror, winreg

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
    assert len(a) == len(b), f'len(a) = {len(a)}, len(b) = {len(b)}'
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

SERVERS_REGISTRY_MAP = {
    'MySQL': r'Software\PremiumSoft\Navicat\Servers',
    'MariaDB': r'Software\PremiumSoft\NavicatMARIADB\Servers',
    'MongoDB': r'Software\PremiumSoft\NavicatMONGODB\Servers',
    'MSSQL': r'Software\PremiumSoft\NavicatMSSQL\Servers',
    'OracleSQL': r'Software\PremiumSoft\NavicatOra\Servers',
    'PostgreSQL': r'Software\PremiumSoft\NavicatPG\Servers',
    'SQLite': r'Software\PremiumSoft\NavicatSQLite\Servers'
}

def regvalue2str(t: tuple[typing.Any, int]):
    reg_value, reg_type = t
    if isinstance(reg_value, str):
        return reg_value
    elif isinstance(reg_value, int):
        return '{:d}'.format(reg_value)
    else:
        raise NotImplementedError()

def decrypt_string(s: str, *ciphers) -> str:
    for cipher in ciphers:
        try:
            return cipher.decrypt_string(s)
        except:
            raise
            continue
    else:
        return '<![FAILED TO DECRYPT]!>'

def main():
    cipher_v1 = NavicatCryptoV1()
    cipher_v2 = NavicatCryptoV2()
    cipher_v3 = NavicatCryptoV3(derive_v3_key_from_navicat_cred(fetch_navicat_cred()))

    config = configparser.ConfigParser()

    for servers_type, servers_registry in SERVERS_REGISTRY_MAP.items():
        try:
            servers_hkey = winreg.OpenKeyEx(winreg.HKEY_CURRENT_USER, servers_registry)
        except WindowsError as e:
            if e.winerror == winerror.ERROR_FILE_NOT_FOUND:
                continue
            else:
                raise

        with servers_hkey:
            for i in itertools.count():
                try:
                    server_name = winreg.EnumKey(servers_hkey, i)
                except WindowsError as e:
                    if e.winerror == winerror.ERROR_NO_MORE_ITEMS:
                        break
                    else:
                        raise

                with winreg.OpenKey(servers_hkey, server_name) as server_hkey:
                    identifier = '{:s}:{:s}'.format(servers_type, server_name)
                    config.add_section(identifier)

                    if servers_type == 'SQLite':
                        config.set(identifier, 'file', regvalue2str(winreg.QueryValueEx(server_hkey, 'DatabaseFileName')))
                    else:
                        config.set(identifier, 'host', regvalue2str(winreg.QueryValueEx(server_hkey, 'Host')))
                        config.set(identifier, 'port', regvalue2str(winreg.QueryValueEx(server_hkey, 'Port')))

                    if servers_type == 'OracleSQL':
                        config.set(identifier, 'database', regvalue2str(winreg.QueryValueEx(server_hkey, 'InitialDatabase')))

                    config.set(identifier, 'username', regvalue2str(winreg.QueryValueEx(server_hkey, 'Username')))

                    try:
                        server_password, _ = winreg.QueryValueEx(server_hkey, 'Pwd')
                        config.set(identifier, 'password', decrypt_string(server_password, cipher_v1, cipher_v2))
                    except WindowsError as e:
                        if e.winerror == winerror.ERROR_FILE_NOT_FOUND:
                            try:
                                server_password, _ = winreg.QueryValueEx(server_hkey, 'Pwd_2')
                                config.set(identifier, 'password', decrypt_string(server_password, cipher_v3))
                            except WindowsError as e:
                                if e.winerror == winerror.ERROR_FILE_NOT_FOUND:
                                    config.set(identifier, 'password', '')
                                else:
                                    raise
                        else:
                            raise

                    try:
                        server_use_ssh, _ = winreg.QueryValueEx(server_hkey, 'UseSSH')
                        assert isinstance(server_use_ssh, int)
                    except WindowsError as e:
                        if e.winerror == winerror.ERROR_FILE_NOT_FOUND:
                            server_use_ssh = 0
                        else:
                            raise

                    if server_use_ssh != 0:
                        config.set(identifier, 'ssh-host', regvalue2str(winreg.QueryValueEx(server_hkey, 'SSH_Host')))
                        config.set(identifier, 'ssh-port', regvalue2str(winreg.QueryValueEx(server_hkey, 'SSH_Port')))

                        config.set(identifier, 'ssh-username', regvalue2str(winreg.QueryValueEx(server_hkey, 'SSH_UserName')))

                        try:
                            server_ssh_password, _ = winreg.QueryValueEx(server_hkey, 'SSH_Password')
                            config.set(identifier, 'ssh-password', decrypt_string(server_ssh_password, cipher_v1, cipher_v2))
                        except WindowsError as e:
                            if e.winerror == winerror.ERROR_FILE_NOT_FOUND:
                                try:
                                    server_ssh_password, _ = winreg.QueryValueEx(server_hkey, 'SSH_Password_2')
                                    config.set(identifier, 'ssh-password', decrypt_string(server_ssh_password, cipher_v3))
                                except WindowsError as e:
                                    if e.winerror == winerror.ERROR_FILE_NOT_FOUND:
                                        config.set(identifier, 'ssh-password', '')
                                    else:
                                        raise
                            else:
                                raise

    config.write(sys.stdout)

if __name__ == '__main__':
    main()
