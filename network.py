#!/usr/bin/env python3
# network.py

import os, sys, getopt, time, json, pickle
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

NET_PATH = './'
ADDR_SPACE = 'A'
CLEAN = False
TIMEOUT = 0.500  # 500 millisec
CLIENT_KEY_SIZE = 2048


def read_msg(src):
    global last_read

    out_dir = NET_PATH + src + '/OUT'
    msgs = sorted(os.listdir(out_dir))

    if len(msgs) - 1 <= last_read[src]:
        return '', ''

    next_msg = msgs[last_read[src] + 1]
    dsts = next_msg.split('--')[1]
    with open(out_dir + '/' + next_msg, 'rb') as f: msg = f.read()

    last_read[src] += 1
    return msg, dsts


def write_msg(dst, msg):
    in_dir = NET_PATH + dst + '/IN'
    msgs = sorted(os.listdir(in_dir))

    if len(msgs) > 0:
        last_msg = msgs[-1]
        next_msg = (int.from_bytes(bytes.fromhex(last_msg), byteorder='big') + 1).to_bytes(2, byteorder='big').hex()
    else:
        next_msg = '0000'

    with open(in_dir + '/' + next_msg, 'wb') as f:
        f.write(msg)

    return


# ------------
# main program
# ------------

try:
    opts, args = getopt.getopt(sys.argv[1:], shortopts='hp:a:c', longopts=['help', 'path=', 'addrspace=', 'clean'])
except getopt.GetoptError:
    print('Usage: python network.py -p <network path> -a <address space> [--clean]')
    sys.exit(1)

# if len(opts) == 0:
# 	print('Usage: python network.py -p <network path> -a <address space> [--clean]')
# 	sys.exit(1)

for opt, arg in opts:
    if opt == '-h' or opt == '--help':
        print('Usage: python network.py -p <network path> -a <address space> [--clean]')
        sys.exit(0)
    elif opt == '-p' or opt == '--path':
        NET_PATH = arg
    elif opt == '-a' or opt == '--addrspace':
        ADDR_SPACE = arg
    elif opt == '-c' or opt == '--clean':
        CLEAN = True

ADDR_SPACE = ''.join(sorted(set(ADDR_SPACE)))

if len(ADDR_SPACE) < 1:
    print('Error: Address space must contain at least 1 addresses.')
    sys.exit(1)

for addr in ADDR_SPACE:
    if addr not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        print('Error: Addresses must be capital letters from the 26-element English alphabet.')
        sys.exit(1)

if (NET_PATH[-1] != '/') and (NET_PATH[-1] != '\\'): NET_PATH += '/'

if not os.access(NET_PATH, os.F_OK):
    print('Error: Cannot access path ' + NET_PATH)
    sys.exit(1)

print('--------------------------------------------')
print('Network is running with the following input:')
print('  Network path: ' + NET_PATH)
print('  Address space: ' + ADDR_SPACE)
print('  Clean-up requested: ', CLEAN)
print('--------------------------------------------')

# create server and generate public and private key for server
server_dir = NET_PATH + 'SERVER'
if not os.path.exists(server_dir):
    # Create server
    print('Folder for address ' + server_dir + ' does not exist. Trying to create it... ', end='')
    os.mkdir(server_dir)
    os.mkdir(server_dir + '/IN')
    os.mkdir(server_dir + '/OUT')
    os.mkdir(server_dir + '/CLIENT_FILES')
    print('Done.')

# create folders for addresses if needed
for addr in ADDR_SPACE:
    addr_dir = NET_PATH + addr
    if not os.path.exists(addr_dir):
        print('Folder for address ' + addr + ' does not exist. Trying to create it... ', end='')
        os.mkdir(addr_dir)
        os.mkdir(addr_dir + '/IN')
        os.mkdir(addr_dir + '/OUT')
        print('Done.')


for addr in ['SERVER']+list(ADDR_SPACE):
    # Generate server's public key and private key
    addr_dir = NET_PATH + addr
    print('Generating %s\'s key pairs... ' % addr)
    key = RSA.generate(2048)

    # private key save in server
    print('Saving %s\'s private key...' % addr)
    private_key = key.export_key()
    private_file_out = open(addr_dir + "/private.pem", "wb")
    private_file_out.write(private_key)
    private_file_out.close()

    # public key save in server
    print('Saving %s\'s public key...')
    public_key = key.publickey().export_key()
    public_file_out = open("./%s_public.pem" % addr, "wb")
    public_file_out.write(public_key)
    public_file_out.close()
    print('Done')

print("Generate salt for server...")
salt = get_random_bytes(16)
with open(NET_PATH+'/SERVER/salt.txt', 'wb') as salt_file:
    salt_file.write(salt)
    salt_file.close()

credentials = {}
hash_passwords = {}
for addr in ADDR_SPACE:
    password = input('Type %s\'s password: ' % addr)
    passphrase = input('Type %s\'s passphrase: ' % addr)
    username = addr
    addr_dir = NET_PATH + addr

    # usename, password, and passphrase is not actually save on client, user will enter it themselves
    # this is only for demonstration purpose
    credentials[username] = {'password': password, 'passphrase': passphrase}
    hash_passwords[bytes(username, 'utf-8')] = scrypt(password, salt, 16, N=2**14, r=8, p=1)
    key = RSA.generate(CLIENT_KEY_SIZE)
    client_key_file = open(addr_dir + '/client_key.pem', 'wb')
    print("Saving key to %s" % addr_dir + '/client_key.pem')
    client_key_file.write(key.export_key('PEM', passphrase=passphrase))
    print('Key saved for %s' % username)
    client_key_file.close()

with open('credentials.json', 'w') as credentials_file:
    json.dump(credentials, credentials_file)
    print('Credential saved')
    credentials_file.close()
with open(NET_PATH + '/SERVER/hash_passwords.pck', 'wb') as hash_passwords_file:
    pickle.dump(hash_passwords, hash_passwords_file, protocol=pickle.HIGHEST_PROTOCOL)
    print('Saved Hash passwords on server')
    hash_passwords_file.close()

# if program was called with --clean, perform clean-up here
# go through the addr folders and delete messages
if CLEAN:
    for addr in list(ADDR_SPACE)+['SERVER']:
        in_dir = NET_PATH + addr + '/IN'
        for f in os.listdir(in_dir): os.remove(in_dir + '/' + f)
        out_dir = NET_PATH + addr + '/OUT'
        for f in os.listdir(out_dir): os.remove(out_dir + '/' + f)

# initialize state (needed for tracking last read messages from OUT dirs)
last_read = {}
for addr in list(ADDR_SPACE)+['SERVER']:
    out_dir = NET_PATH + addr + '/OUT'
    msgs = sorted(os.listdir(out_dir))
    last_read[addr] = len(msgs) - 1

# main loop
print('Main loop started, quit with pressing CTRL-C...')
while True:
    time.sleep(TIMEOUT)
    for src in list(ADDR_SPACE)+['SERVER']:
        msg, dsts = read_msg(src)  # read outgoing message
        if dsts != '':  # if read returned a message...
            if dsts == '+': dsts = ADDR_SPACE  # handle broadcast address +
            write_msg(dsts, msg)  # write incoming message
