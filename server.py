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
USR_DIR = '.'
CUR_PATH = ''
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


def make_directory(path):
    if not os.path.exists(path):
        os.makedirs(path)


def remove_directory(path):
    if os.path.exists(path):
        shutil.rmtree(path)


def remove_file(path):
    if os.path.exists(path) and not os.path.isdir(path) and not os.path.islink(path):
        os.remove(path)
        

def upload_message(fileMessage, path):
    f = open("./" + "SERVER/CLIENT_FILES/" + username.decode('utf-8') + "/" + path, "wb+")
    f.write(fileMessage)
    f.close()


def download_message(path):
    try:
        f = open("./" + "SERVER/CLIENT_FILES/" + username.decode('utf-8') + "/" + path, "rb")
        data = f.read()
        f.close()
        return data
    except IOError:
        return None


def check_valid_exist_path(full_path, user_path):
    working_path = os.path.normpath(full_path).replace(os.sep, '/')
    if not os.path.exists("./" + working_path):
        print(f"Cannot find path {working_path}")
        return False
    else:
        print(f"Working path {working_path}")
        if user_path in working_path:
            print(f"Found {working_path}")
            return True
        else:
            return False


def check_valid_new_path(full_path, user_path):
    working_path = os.path.normpath(full_path).replace(os.sep, '/')
    print(f"Working path {working_path}")
    if user_path in working_path:
        print(f"Found {working_path}")
        return True
    else:
        return False


def get_path(file_path):
    globals()
    if len(CUR_PATH) == 0:
        user_path = OWN_ADDR + f"/{CLIENT_DIR}" + f"/{USR_DIR}"
    else:
        user_path = OWN_ADDR + f"/{CLIENT_DIR}" + f"/{CUR_PATH}"

    full_path = NET_PATH + user_path + f"/{file_path}"
    check_path = os.path.split(full_path)

    if check_valid_exist_path(check_path[0], user_path):
        working_path = os.path.normpath(full_path).replace(os.sep, '/')
        cur_dir = working_path.replace(f"SERVER/CLIENT_FILES/{USR_DIR}/", "")
        return cur_dir
    else:
        return None


def get_current_path():
    globals()
    if len(CUR_PATH) == 0:
        user_path = OWN_ADDR + f"/{CLIENT_DIR}" + f"/{USR_DIR}"
    else:
        user_path = OWN_ADDR + f"/{CLIENT_DIR}" + f"/{CUR_PATH}"
    return user_path


def encrypt_message(command, path=None, enc_file=None):
    globals()

    timestamp = str(time.time()).encode('utf-8')
    length_timestamp = len(timestamp).to_bytes(length=2, byteorder='big')

    length_path = 0 if path is None else len(path)
    length_path = length_path.to_bytes(length=2, byteorder='big')
    path = b"" if path is None else path.encode('utf-8')

    length_enc_file = 0 if enc_file is None else len(enc_file)
    length_enc_file = length_enc_file.to_bytes(length=2, byteorder='big')
    enc_file = b"" if enc_file is None else enc_file

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
    if length_enc_file == 0:
        enc_file = None

    global current_timestamp
    print("Message timestamp and current timestamp")
    print(timestamp, current_timestamp)
    if timestamp < current_timestamp:
        print("Timestamp is invalid!")
        return None, None, None
    current_timestamp = timestamp

    global CUR_PATH
    print("Command is %s" % command)

    if command == 'MKD':
        user_path = OWN_ADDR + f"/{CLIENT_DIR}" + f"/{USR_DIR}"
        cur_path = get_current_path()
        target = f"/{path}"
        full_path = NET_PATH + cur_path + target
        if check_valid_new_path(full_path, user_path):
            make_directory(full_path)
            print(f"Make Directory: {path}")
        else:
            path = None

    elif command == 'RMD':
        user_path = OWN_ADDR + f"/{CLIENT_DIR}" + f"/{USR_DIR}"
        current_path = get_current_path()
        target = f"/{path}"
        full_path = NET_PATH + current_path + target
        if check_valid_new_path(full_path, user_path):
            remove_directory(full_path)
            print(f"Remove Directory: {path}")
        else:
            path = None

    elif command == 'GWD':
        path = '.' if len(CUR_PATH) == 0 else '.' + CUR_PATH[len(username):]
        print(f"Current Directory: {CUR_PATH}")

    elif command == 'CWD':
        user_path = OWN_ADDR + f"/{CLIENT_DIR}" + f"/{USR_DIR}"
        current_path = get_current_path()
        target = f"/{path}"
        full_path = NET_PATH + current_path + target

        if check_valid_exist_path(full_path, user_path):
            working_path = os.path.normpath(full_path).replace(os.sep, '/')
            CUR_PATH = working_path.replace("SERVER/CLIENT_FILES/", "")
            path = '.' + CUR_PATH[len(username):]
            print(f"Change Directory to: {CUR_PATH}")
        else:
            path = None

    elif command == 'LST':
        # listing the content of a folder on the server
        path = NET_PATH + OWN_ADDR + ((f"/{CLIENT_DIR}" + f"/{CUR_PATH}") if len(CUR_PATH) > 0
                                      else (f"/{CLIENT_DIR}" + f"/{USR_DIR}"))

        files = []
        # r = root, d = directories, f = files
        for r, d, f in os.walk(path):
            for folder in d:
                files.append(f"{folder}")
            for file in f:
                files.append(file)
            break  # only want one level
        path = '\n'.join(files)
        print("List in Directory:")
        print(path)

    elif command == 'UPL':
        path = get_path(path)
        if path is not None:
            print(f"Upload path is: \n{path}")
            upload_message(enc_file, path)
        enc_file = None

    elif command == 'DNL':
        path = get_path(path)
        if path is not None:
            print(f"Download path is: \n{path}")
            enc_file = download_message(path)

    elif command == 'RMF':
        user_path = OWN_ADDR + f"/{CLIENT_DIR}" + f"/{USR_DIR}"
        current_path = get_current_path()
        target = f"/{path}"
        full_path = NET_PATH + current_path + target
        if check_valid_new_path(full_path, user_path):
            remove_file(full_path)
            print(f"Remove file in path is: \n{path}")
        else:
            path = None

    elif command == 'EXT':
        print("User Log Out!")

    else:
        print('Invalid command')
        return command, None, None

    return command, path, enc_file


current_timestamp = -1
print('Main loop started...')
while True:
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
        if command:
            print("Message is decrypted. Sending response to client")
            netif.send_msg(encrypt_message(command, path, enc_file), username.decode('utf-8'))
            print("Response is sent to client")
