#!/usr/bin/env python3
# client.py

import os, sys, getopt, json, time
from netinterface import network_interface
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes

NET_PATH = './'
OWN_ADDR = 'A'
SERVER_NAME = 'SERVER'

# ------------       
# main program
# ------------

try:
    opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:', longopts=['help', 'path=', 'addr='])
except getopt.GetoptError:
    print('Usage: python client.py -p <network path> -a <own addr>')
    sys.exit(1)

for opt, arg in opts:
    if opt == '-h' or opt == '--help':
        print('Usage: python client.py -p <network path> -a <own addr>')
        sys.exit(0)
    elif opt == '-p' or opt == '--path':
        NET_PATH = arg
    elif opt == '-a' or opt == '--addr':
        OWN_ADDR = arg

if (NET_PATH[-1] != '/') and (NET_PATH[-1] != '\\'): NET_PATH += '/'

if not os.access(NET_PATH, os.F_OK):
    print('Error: Cannot access path ' + NET_PATH)
    sys.exit(1)

if len(OWN_ADDR) > 1: OWN_ADDR = OWN_ADDR[0]

if OWN_ADDR not in network_interface.addr_space:
    print('Error: Invalid address ' + OWN_ADDR)
    sys.exit(1)


def check_client_credential(client_credential, user_input, type):
    globals()
    count = 0
    while count < 3 and client_credential != user_input:
        print("Wrong %s" % type)
        user_input = input('Type %s\'s %s' % (OWN_ADDR, type))
        count += 1
    if count == 3:
        print("Too many trials. Logging out...")
        sys.exit(1)
    return user_input


def get_client_key(passphrase):
    f = open(netif.addr_dir + '/client_key.pem', 'r')
    return RSA.import_key(f.read(), passphrase=passphrase)


def process_enc_file(enc_file):
    enc_file_key = enc_file[:256]
    nonce = enc_file[256:272]
    length_ciphertext = int.from_bytes(enc_file[272:274], byteorder='big')
    ciphertext = enc_file[274:274+length_ciphertext]
    tag = enc_file[274+length_ciphertext:]
    return [enc_file_key, nonce, ciphertext, tag]


def encrypt_file(file):
    globals()
    print("Encrypting file...")
    file = file.encode('utf-8')
    print("Generating file's key...")
    file_key = get_random_bytes(16)
    print("Encrypting file...")
    cipher_aes = AES.new(file_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(file)
    print("File encrypted.")
    print("Encrypting file key...")
    enc_file_key = cipher_rsa.encrypt(file_key)
    print(len(enc_file_key))
    print("Key encrypted")
    enc_file = b''.join([enc_file_key,
                        cipher_aes.nonce,
                        len(ciphertext).to_bytes(length=2, byteorder='big'),
                        ciphertext,
                        tag])
    return enc_file


def decrypt_file(enc_file):
    print("Decrypting encrypted file")
    [enc_file_key, nonce, ciphertext, tag] = process_enc_file(enc_file)
    print("Decrypting file key...")
    file_key = cipher_rsa.decrypt(enc_file_key)
    print("File key decrypted")
    print("Decrypting file...")
    cipher_aes = AES.new(file_key, AES.MODE_EAX, nonce)
    file = cipher_aes.decrypt_and_verify(ciphertext, tag)
    print("File is decrypted. Result: %s" % file.decode("utf-8"))
    return file


def encrypt_message(command, path="", file=""):
    globals()

    timestamp = str(time.time()).encode('utf-8')
    length_timestamp = len(timestamp).to_bytes(length=2, byteorder='big')

    path = path.encode('utf-8')
    length_path = len(path).to_bytes(length=2, byteorder='big')

    enc_file, length_enc_file = b"", 0
    if file != "":
        enc_file = encrypt_file(file)
        length_enc_file = len(enc_file).to_bytes(length=2, byteorder='big')

    command = command.encode('utf-8')

    msg = b''.join([length_timestamp,
                    timestamp,
                    command,
                    length_path,
                    path,
                    length_enc_file,
                    enc_file])

    cipher_aes = AES.new(session_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(msg)
    return cipher_aes.nonce, tag, ciphertext


def decrypt_server_message(msg):
    globals()
    nonce, tag, ciphertext = msg[:16], msg[16:32], msg[32:]
    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce)
    enc_file = cipher_aes.decrypt_and_verify(ciphertext, tag)
    if enc_file != "":
        file = decrypt_file(enc_file)
        return file


netif = network_interface(NET_PATH, OWN_ADDR)

password = input('Type %s\'s password: ' % OWN_ADDR)
passphrase = input('Type %s\'s passphrase: ' % OWN_ADDR)
print("Logging In...")
with open('credentials.json') as in_file:
    credentials = json.load(in_file)
    if credentials[OWN_ADDR]['password'] == password and credentials[OWN_ADDR]['passphrase'] == passphrase:
        client_key = get_client_key(passphrase)
    else:
        if credentials[OWN_ADDR]['password'] != password:
            password = check_client_credential(credentials[OWN_ADDR]['password'], password, 'password')
        if credentials[OWN_ADDR]['passphrase'] != passphrase:
            passphrase = check_client_credential(credentials[OWN_ADDR]['passphrase'], passphrase, 'passphrase')

client_key = get_client_key(passphrase)
cipher_rsa = PKCS1_OAEP.new(client_key)
print('Successfully get client\'s key!')
print("Logged in")


print("Generating session key...")
session_key = get_random_bytes(16)
netif.ebtablish_session_key(session_key, OWN_ADDR, password)

print("Encrypting session key...")
cipher_aes = AES.new(session_key, AES.MODE_GCM)
data = b''.join([len(OWN_ADDR.encode('utf-8')).to_bytes(2, byteorder='big'),
                 OWN_ADDR.encode('utf-8'),
                 len(password.encode('utf-8')).to_bytes(2, byteorder='big'),
                 password.encode('utf-8')])
ciphertext, tag = cipher_aes.encrypt_and_digest(data)
session_key_msg = (cipher_aes.nonce, tag, ciphertext)

print("Sending encrypted session key to server...")
netif.send_msg(session_key_msg, SERVER_NAME)

while True:
    # Client send message
    command = input('Type a command: ').upper()
    file_path = input('Type a file path (leave Blank if not needed): ')
    file = input('Type a text message (leave Blank if not needed): ')
    print("Encrypting message...")
    netif.send_msg(encrypt_message(command, file_path, file), SERVER_NAME)
    print("Message is encrypted and sent. Waiting for response from server...")

    # Client receive message
    status, server_msg = netif.receive_msg(blocking=True)  # when returns, status is True and msg contains a message
    print("Received response from server. Checking session key")
    enc_session_key_from_server_msg = server_msg[:len(netif.enc_session_key)]
    if enc_session_key_from_server_msg != netif.enc_session_key:
        print('Wrong Session Key')
        break
    print("Session Key authenticated. Decrypting the server response...")
    server_msg = server_msg[len(netif.enc_session_key):]
    response = decrypt_server_message(server_msg)
    if input('Continue? (y/n): ') == 'n':
        netif.send_msg(encrypt_message('EXT'), SERVER_NAME)
        break
