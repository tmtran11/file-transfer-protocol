#!/usr/bin/env python3
# server.py

import os, sys, getopt, pickle, time
from netinterface import network_interface
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import scrypt
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import shutil


NET_PATH = './'
OWN_ADDR = 'SERVER'
CLIENT_DIR = 'CLIENT_FILES'
USR_DIR = '.'#A
CUR_PATH = ''#result of os.path.normpath
current_timestamp = time.time()
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
private_key = RSA.import_key(open("./%s/private.pem" % netif.server_name).read())
cipher_rsa = PKCS1_OAEP.new(private_key)
salt = open(NET_PATH + '%s/salt.txt' % netif.server_name, 'rb').read()


def ebstablish_session_key(msg):
    globals()
    timestamp, enc_session_key, signature = msg[:8], msg[8:264], msg[-256:]
    global current_timestamp
    if float(int.from_bytes(timestamp, byteorder='big')) < current_timestamp:
        print("Timestamp not valid")
        return None, None
    current_timestamp = float(int.from_bytes(timestamp, byteorder='big'))
    print("Decrypting Session key using server's private key...")
    data = cipher_rsa.decrypt(enc_session_key)
    username, password = process_user_credential(data[:-16])
    user_authenticated = authenticate_user(username, password)
    if user_authenticated:
        client_public_key = RSA.import_key(open(netif.net_path + "/%s_public.pem" % username.decode('utf-8'), "r").read())
        h = SHA256.new(b''.join([netif.server_name.encode('utf-8'), timestamp, enc_session_key]))
        print("Verifying signature using %s\'s public key..." % username.decode('utf-8'))
        try:
            pkcs1_15.new(client_public_key).verify(h, signature)
            print("Signature verified!")
            session_key = data[-16:]
            return session_key, username
        except (ValueError, TypeError):
            print("Signature is invalid")
            return None, None
    else:
        return None, None


def process_user_credential(msg):
    length_username = int.from_bytes(msg[:2], byteorder='big')
    username = msg[2:2+length_username]
    length_password = int.from_bytes(msg[2+length_username:4+length_username], byteorder='big')
    password = msg[-length_password:]
    return username, password


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
    with open(NET_PATH + '%s/hash_passwords.pck' % netif.server_name, 'rb') as f:
        hash_passwords = pickle.load(f)
        if scrypt(password, salt, 16, N=2 ** 14, r=8, p=1) == hash_passwords[username]:
            print("User authentication success!")
            global USR_DIR
            USR_DIR = username.decode("utf-8")
            print("Set user dir to %s" % username.decode("utf-8"))
            user_dir = NET_PATH + OWN_ADDR + f"/{CLIENT_DIR}" + f"/{USR_DIR}"
            if not os.path.exists(user_dir):
                os.mkdir(user_dir)

            return True
        else:
            print('User authentication of %s fail' % username)
            return False


def upload_message(fileMessage, path):
    i = len(path)
    while path[i - 1] != '/':
        i -= 1
    path_to_check = path[0:i]

    if not (os.path.exists("./" + "SERVER/CLIENT_FILES/" + username.decode('utf-8') + "/" + path_to_check)):
        os.makedirs("./" + "SERVER/CLIENT_FILES/" + username.decode('utf-8') + "/" + path_to_check)

    f = open("./" + "SERVER/CLIENT_FILES/" + username.decode('utf-8') + "/" + path, "wb+")
    f.write(fileMessage)
    f.close()


def download_message(path):
    file_return = ""
    try:
        f = open("./" + "SERVER/CLIENT_FILES/" + username.decode('utf-8') + "/" + path, "rb")
        file_return = f.read()
        f.close()
    except IOError:
        file_return = "".encode('utf-8')

    return file_return


def encrypt_message(command, path=None, enc_file=None):
    globals()

    timestamp = str(time.time()).encode('utf-8')
    length_timestamp = len(timestamp).to_bytes(length=2, byteorder='big')

    path = b"" if path is None else path.encode('utf-8')
    length_path = 0 if path is None else len(path)
    length_path = length_path.to_bytes(length=2, byteorder='big')

    enc_file = b"" if enc_file is None else enc_file
    length_enc_file = 0 if enc_file is None else len(enc_file)
    length_enc_file = length_enc_file.to_bytes(length=2, byteorder='big')

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
    return b''.join([cipher_aes.nonce, tag, ciphertext])


def decrypt_message(msg):
    globals()
    nonce, tag, ciphertext = msg[:16], msg[16:32], msg[32:]
    cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    [timestamp, command, length_path, path, length_enc_file, enc_file] = process_client_msg(data)
    global current_timestamp
    if timestamp < current_timestamp:
        print("Timestamp is invalid!")
        return None, None, None
    current_timestamp = timestamp
    global CUR_PATH
    print("Command is %s" % command)
    if command == 'MKD':
        user_path = OWN_ADDR + f"/{CLIENT_DIR}" + f"/{USR_DIR}"
        target = f"/{path}"
        full_path = NET_PATH + user_path + target
        
        if not os.path.exists(full_path):
            os.makedirs(f"SERVER/CLIENT_FILES/{USR_DIR}/{path}")
    elif command == 'RMD':
        shutil.rmtree(f"SERVER/CLIENT_FILES/{USR_DIR}/{path}")
    elif command == 'GWD':
        # asking for the name of the  current folder (working directory) on the server
        print(f"Current Directory: {CUR_PATH}")
        path = '.' + CUR_PATH[len(username):]
    elif command == 'CWD':
        # changing the current folder on the server
        user_path = OWN_ADDR + f"/{CLIENT_DIR}" + f"/{USR_DIR}"
        target = f"/{path}"
        full_path = NET_PATH + user_path + target

        if not os.path.exists(full_path):
            print(f"1Cannot find path {full_path}")
            path = ""
        else:
            working_path = os.path.normpath(full_path).replace(os.sep, '/')
            print(f"Working path {working_path}")
            if user_path in working_path:
                print(f"Found {working_path}")
                # only return A/...
                CUR_PATH = working_path.replace("SERVER/CLIENT_FILES/", "")
                print(f"Cur Dir: {CUR_PATH}")
                path = '.'+CUR_PATH[len(username):]
            else:
                print(f"2Cannot find path {working_path}")
                path = ""
    elif command == 'LST':
        # listing the content of a folder on the server
        if len(CUR_PATH) > 0:
            path = NET_PATH + OWN_ADDR + f"/{CLIENT_DIR}" + f"/{CUR_PATH}"
        else:
            path = NET_PATH + OWN_ADDR + f"/{CLIENT_DIR}" + f"/{USR_DIR}"
        print(f"path = {path}")

        files = []
        # r=root, d=directories, f = files
        for r, d, f in os.walk(path):
            for folder in d:
                files.append(f"{folder}")
            for file in f:
                files.append(file)
            break  # only want one level
        path = '\n'.join(files)
    elif command == 'UPL':
        upload_message(enc_file, path)
    elif command == 'DNL':
        enc_file = download_message(path)
    elif command == 'RMF':
        os.remove(f"SERVER/CLIENT_FILES/{USR_DIR}/{path}")
    elif command == 'EXT':
        print("User Log Out!")
    else:
        print('Invalid command')

    return command, path, enc_file


current_timestamp = -1
print('Main loop started...')
while True:
    # Establish session key
    status, session_key_msg = netif.receive_msg(blocking=True) # when returns, status is True and msg contains a message
    session_key, username = ebstablish_session_key(session_key_msg)
    if session_key is None:
        netif.send_msg(encrypt_message(command='EXT'), username.decode('utf-8'))
        break
    netif.send_msg(encrypt_message(command='ENT'), username.decode('utf-8'))
    print("Session key established with client %s!" % username.decode('utf-8'))

    while True:
        _, msg = netif.receive_msg(blocking=True)  # when returns, status is True and msg contains a message
        print("Received message from client. Decrypting client message...")
        command, path, enc_file = decrypt_message(msg)
        if command == 'EXT':
            break
        print("Message is decrypted. Sending response to client")
        netif.send_msg(encrypt_message(command, path, enc_file), username.decode('utf-8'))
        print("Response is sent to client")
