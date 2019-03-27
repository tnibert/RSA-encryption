#! /usr/bin/env python3
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

"""
This script provides functions to generate an RSA private/public key pair and encrypt/decrypt files
"""


def encrypt(filename, enc_filename, public_key):
    """
    Encrypts a file using the given public_key
    : param filename: file to encrypt
    : param enc_filename: file to save encrypted data to
    : param public_key: file name of the public key to use
    """

    with open(enc_filename, 'wb') as out_file:
        recipient_key = RSA.import_key(open(public_key).read())
        session_key = get_random_bytes(16)

        cipher_rsa = PKCS1_OAEP.new(recipient_key)
        out_file.write(cipher_rsa.encrypt(session_key))

        cipher_aes = AES.new(session_key, AES.MODE_EAX)

        with open(filename, "rb") as fi:
            data = fi.read()

        ciphertext, tag = cipher_aes.encrypt_and_digest(data)

        out_file.write(cipher_aes.nonce)
        out_file.write(tag)
        out_file.write(ciphertext)


def decrypt(passphrase, enc_filename, private_key):
    """
    Decrypts the file enc_filename
    : param passphrase: passphrase to decrypt, same as provided to genkey()
    : param enc_filename: filename of encrypted file
    : param private_key: filename of private key
    : return: decrypted data
    """

    with open(enc_filename, 'rb') as fobj:
        private_key = RSA.import_key(
            open(private_key).read(),
            passphrase=passphrase)

        enc_session_key, nonce, tag, ciphertext = [ fobj.read(x)
                                                for x in (private_key.size_in_bytes(),
                                                16, 16, -1) ]

        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return data


def genkey(passphrase):
    """
    Generate an RSA private/public keypair
    : param passphrase: passphrase for RSA keypair
    : return: private and public keys
    """
    code = passphrase
    key = RSA.generate(2048)
    private_key = key.exportKey(passphrase=code, pkcs=8,
        protection="scryptAndAES128-CBC")
    public_key = key.publickey().exportKey()

    return private_key, public_key


def writekeystofile(private_key, public_key, priv_fname, pub_fname):
    """
    Write the RSA keys to files
    : param private_key: private key to save
    : param public_key: public key to save
    : param priv_fname: filename to save private key to
    : param pub_fname: filename to save public key to
    """
    with open(priv_fname, 'wb') as f:
        f.write(private_key)
    with open(pub_fname, 'wb') as f:
        f.write(public_key)


if __name__ == '__main__':
    password = "atestpass"
    privkey_fname = 'my_private_rsa_key.bin'
    pubkey_fname = 'my_rsa_public.pem'

    # create keys
    priv, pub = genkey(password)
    writekeystofile(priv, pub, privkey_fname, pubkey_fname)

    # encrypt and decrypt a file
    encrypt('test.txt', 'encrypted_data.bin', pubkey_fname)
    print(decrypt(password, 'encrypted_data.bin', privkey_fname))
