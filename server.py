#!/usr/bin/env python3
# server.py

import os, sys, getopt, pickle, time
from netinterface import network_interface
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import scrypt

NET_PATH = './'
OWN_ADDR = 'SERVER'

# ------------       
# main program
# ------------

try:
    opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:p:', longopts=['help', 'path='])
except getopt.GetoptError:
    print('Usage: python server.py -p <network path>')
    sys.exit(1)

for opt, arg in opts:
    if opt == '-h' or opt == '--help':
        print('Usage: python server.py -p <network path>')
        sys.exit(0)
    elif opt == '-p' or opt == '--path':
        NET_PATH = arg

if (NET_PATH[-1] != '/') and (NET_PATH[-1] != '\\'): NET_PATH += '/'

if not os.access(NET_PATH, os.F_OK):
    print('Error: Cannot access path ' + NET_PATH)
    sys.exit(1)

# main loop
netif = network_interface(NET_PATH, OWN_ADDR)

print("Getting private key and salt")
private_key = RSA.import_key(open("./SERVER/private.pem").read())
cipher_rsa = PKCS1_OAEP.new(private_key)
salt = open(NET_PATH + 'SERVER/salt.txt', 'rb').read()


def process_session_key_msg(msg):
    enc_session_key = msg[:private_key.size_in_bytes()]
    nonce = msg[len(enc_session_key):len(enc_session_key) + 16]
    tag = msg[len(enc_session_key) + len(nonce):len(enc_session_key) + len(nonce) + 16]
    ciphertext = msg[len(enc_session_key) + len(nonce) + len(tag):]
    return [enc_session_key, nonce, tag, ciphertext]


def process_user_credential(msg):
    length_username = int.from_bytes(msg[:2], byteorder='big')
    username = msg[2:2+length_username]
    length_password = int.from_bytes(msg[2+length_username:4+length_username], byteorder='big')
    password = msg[-length_password:]
    return [username, password]


def process_client_msg(msg):
    length_timestamp = int.from_bytes(msg[:2], byteorder='big')
    timestamp = float(msg[2:length_timestamp+2].decode('utf-8'))
    command = msg[length_timestamp+2:length_timestamp+5].decode('utf-8')
    length_path = int.from_bytes(msg[length_timestamp+5:length_timestamp+7], byteorder='big')
    path = msg[length_timestamp+7:length_timestamp+length_path+7].decode('utf-8')
    length_enc_file = int.from_bytes(msg[length_timestamp+length_path+7:length_timestamp+length_path+9], byteorder='big')
    enc_file = msg[-length_enc_file:]
    return [timestamp, command, length_path, path, length_enc_file, enc_file]


def authenticate_user(username, password):
    globals()
    with open(NET_PATH + 'SERVER/hash_passwords.pck', 'rb') as f:
        hash_passwords = pickle.load(f)
        if scrypt(password, salt, 16, N=2 ** 14, r=8, p=1) == hash_passwords[username]:
            netif.enc_session_key = enc_session_key
            print("User authentication success. Session key is ebstablished")
            return True
        else:
            print('User authentication of %s fail' % username)
            return False


def encrypt_message(msg):
    # TODO: Define responses format
    cipher_aes = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(msg)
    return cipher_aes.nonce, tag, ciphertext


def decrypt_message(msg):
    nonce, tag, ciphertext = msg[:16], msg[16:32], msg[32:]
    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    [timestamp, command, length_path, path, length_enc_file, enc_file] = process_client_msg(data)

    status = None
    # TODO: Define responses format
    if command == 'MKD':
        pass
    elif command == 'RMD':
        pass
    elif command == 'GWD':
        pass
    elif command == 'CWD':
        pass
    elif command == 'LST':
        pass
    elif command == 'UPL':
        pass
    elif command == 'DNL':
        pass
    elif command == 'RML':
        pass
    elif command=='EXT':
        pass
    else:
        print('Invalid command')

    return command, enc_file


print('Main loop started...')
while True:
    # Ebtablish session key
    status, session_key_msg = netif.receive_msg(blocking=True)  # when returns, status is True and msg contains a message
    [enc_session_key, nonce, tag, ciphertext] = process_session_key_msg(session_key_msg)
    print("Server receive encrypted session key")

    # Decrypt the session key with the private RSA key
    session_key = cipher_rsa.decrypt(enc_session_key)
    print("Server obtain session key")

    # Decrypt username and password with session key
    cipher_aes_gcm = AES.new(session_key, AES.MODE_GCM, nonce)
    enc_user_credential = cipher_aes_gcm.decrypt_and_verify(ciphertext, tag)
    print("Server decrypt username and password")

    [username, password] = process_user_credential(enc_user_credential)
    if not authenticate_user(username, password):
        continue

    while True:
        status, msg = netif.receive_msg(blocking=True)  # when returns, status is True and msg contains a message
        print("Received message from client. Checking session key")
        enc_session_key_msg = msg[:len(netif.enc_session_key)]
        if cipher_rsa.decrypt(enc_session_key_msg) != session_key:
            print('Wrong Session Key')
            break
        print("Session Key authenticated. Decrypting the message...")
        msg = msg[len(netif.enc_session_key):]
        command, response = decrypt_message(msg)
        print("Message is decrypted. Sending response to client")
        if command == 'EXT':
            break
        netif.send_msg(encrypt_message(response), username.decode('utf-8'))
        print("Response is sent to client")
