#!/usr/bin/env python3
# netinterface.py

import os, time
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


class network_interface:
    timeout = 0.800  # 800 millisec
    addr_space = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    own_addr = ''
    net_path = ''
    addr_dir = ''
    last_read = -1
    enc_session_key = None

    def __init__(self, path, addr):
        self.net_path = path
        self.own_addr = addr

        addr_dir = self.net_path + self.own_addr
        self.addr_dir = addr_dir
        if not os.path.exists(addr_dir):
            os.mkdir(addr_dir)
            os.mkdir(addr_dir + '/IN')
            os.mkdir(addr_dir + '/OUT')

        in_dir = addr_dir + '/IN'
        msgs = sorted(os.listdir(in_dir))
        self.last_read = len(msgs) - 1

    def ebtablish_session_key(self, session_key, username, password):
        print("Ebtablishing session key")
        f = open(self.net_path+"/public.pem", "r")
        public_key = RSA.import_key(f.read())
        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(public_key)
        self.enc_session_key = cipher_rsa.encrypt(session_key)
        print("Session key is ebtablished!")

        # Encrypt the data with the AES session key

    def send_msg(self, msg, destination):
        out_dir = self.net_path + self.own_addr + '/OUT'
        msgs = sorted(os.listdir(out_dir))

        if len(msgs) > 0:
            last_msg = msgs[-1].split('--')[0]
            next_msg = (int.from_bytes(bytes.fromhex(last_msg), byteorder='big') + 1).to_bytes(2, byteorder='big').hex()
        else:
            next_msg = '0000'

        next_msg += '--' + destination

        (nonce, tag, ciphertext) = msg
        with open(out_dir + '/' + next_msg, 'wb') as f:
            [f.write(x) for x in (self.enc_session_key, nonce, tag, ciphertext)]

        return True

    def receive_msg(self, blocking=False):
        in_dir = self.net_path + self.own_addr + '/IN'

        status = False

        while True:
            msgs = sorted(os.listdir(in_dir))
            if len(msgs) - 1 > self.last_read:
                status = True
                self.last_read += 1

            if not blocking or status:
                with open(in_dir + '/' + msgs[self.last_read], 'rb') as f:
                    return status, f.read()
            else:
                time.sleep(self.timeout)