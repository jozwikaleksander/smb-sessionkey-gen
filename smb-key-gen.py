#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
+----------------------------------------------------------+
| ----------- Random SMB2 Session Key Generator ---------- |
|                                                          |
|  Author:          Aleksander Jóźwik (@jozwikaleksander)  |
|  Creation date:   10-08-2024                             |
|                                                          |                     
+----------------------------------------------------------+
"""
import hashlib
import hmac
import argparse
import logging
from binascii import unhexlify, hexlify
from Cryptodome.Cipher import ARC4

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')


def generate_ntlm_hash(password=None, nt_hash=None):
    """
    Generate NTLM hash from the provided password or return the existing NT hash.

    :param password: User's password (string)
    :param nt_hash: NT hash (string in hex)
    :return: NTLM hash in bytes
    """
    if nt_hash:
        return unhexlify(nt_hash)
    if password:
        return hashlib.new('md4', password.encode('utf-16le')).digest()
    raise ValueError("You need to provide either a password or an NT hash.")


def calculate_response_nt_key(ntlmHash, user, domain):
    """
    Calculate the ResponseNTKey using the NTLM hash, user, and domain.

    :param ntlmHash: NTLM hash in bytes
    :param user: Upper-cased user name in bytes (UTF-16LE encoded)
    :param domain: Upper-cased domain name in bytes (UTF-16LE encoded)
    :return: ResponseNTKey in bytes
    """
    hmac_md5 = hmac.new(ntlmHash, digestmod=hashlib.md5)
    hmac_md5.update(user + domain)
    return hmac_md5.digest()


def calculate_key_exchange_key(responseNtKey, ntProofStr):
    """
    Calculate the KeyExchangeKey using the ResponseNTKey and NTProofStr.

    :param responseNtKey: ResponseNTKey in bytes
    :param ntProofStr: NTProofStr in bytes (hex decoded)
    :return: KeyExchangeKey in bytes
    """
    hmac_md5 = hmac.new(responseNtKey, digestmod=hashlib.md5)
    hmac_md5.update(ntProofStr)
    return hmac_md5.digest()


def decrypt_session_key(keyExchangeKey, encrypted_key):
    """
    Decrypt the session key using RC4 and the KeyExchangeKey.

    :param keyExchangeKey: KeyExchangeKey in bytes
    :param encrypted_key: Encrypted session key in bytes (hex decoded)
    :return: Decrypted session key in bytes
    """
    rc4 = ARC4.new(keyExchangeKey)
    return rc4.encrypt(encrypted_key)


def parse_arguments():
    """
    Parse command-line arguments.
    
    :return: Parsed arguments
    """
    parser = argparse.ArgumentParser(prog='SMB Session Key Generator', description='Generates random decrypted SMB2 session key')
    
    # Required Arguments
    parser.add_argument('-u', '--user', required=True, help="User name")
    parser.add_argument('-d', '--domain', required=True, help="Domain name")
    parser.add_argument('-n', '--ntproofstr', required=True, help="NTProofStr (hex encoded)")
    parser.add_argument('-k', '--key', required=True, help="Encrypted Session Key (hex encoded)")
    
    # Optional Arguments
    parser.add_argument('-p', '--password', help="User's password")
    parser.add_argument('--ntHash', help="NT hash in hex")
    parser.add_argument('-v', '--verbose', action='store_true', help="Increase output verbosity")
    
    return parser.parse_args()


def main():
    args = parse_arguments()

    # Transforming user and domain to uppercase and converting to bytes
    user = args.user.upper().encode('utf-16le')
    domain = args.domain.upper().encode('utf-16le')

    try:
        # Generating an NTLM hash and converting it to bytes
        ntlmHash = generate_ntlm_hash(password=args.password, nt_hash=args.ntHash)

        # Generating ResponseNTKey
        responseNtKey = calculate_response_nt_key(ntlmHash, user, domain)

        # Converting NTPROOFSTR to bytes
        ntProofStr = unhexlify(args.ntproofstr)

        # Calculating KeyExchangeKey using NTPROOFSTR and ResponseNTKey
        keyExchangeKey = calculate_key_exchange_key(responseNtKey, ntProofStr)

        # Generating decrypted session key
        sessionKey = decrypt_session_key(keyExchangeKey, unhexlify(args.key))
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return

    # Output results
    if args.verbose:
        logging.info(f"Username: {args.user.upper()}")
        logging.info(f"Domain: {args.domain.upper()}")
        if args.password:
            logging.info(f"Password: {args.password}")
        if args.ntHash:
            logging.info(f"NT hash: {args.ntHash}")
        logging.info(f"Ntproofstr: {args.ntproofstr}")
        logging.info(f"Session key: {args.key}")
        logging.info(f"Random generated session key: {hexlify(sessionKey).decode()}")
    else:
        print(hexlify(sessionKey).decode())


if __name__ == '__main__':
    main()