from __future__ import print_function

import SocketServer
import logging
import socket
import sys
import os

from abc import ABCMeta

# Commit Random generators
from Crypto.Random.random import StrongRandom
from numpy.random import geometric
from numpy.random import random_integers

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Hash import HMAC
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Signature import PKCS1_PSS
from struct import *
import cPickle as pickle

logger = logging.getLogger(__name__)

BLUE = '\033[94m'
GREEN = '\033[92m'
RED = '\033[91m'
END = '\033[0m'

KEY_SIZE = 2048
MAX_PACKET_LENGTH = 8192
MAX_COMMIT = 10000
MIN_COMMIT = 5
DISTRIBUTION = 'G'

TIMEOUT = 1

class MySocket(object):
    __metaclass__ = ABCMeta

    def close(self):
        try:
            self.socket.close()
        except Exception as e:
            pass

    def commit(self, nbmsg):
        for x in xrange(int(nbmsg)):
            self.send('OK {0}'.format(x), True)
            self.recv(True)

    def send(self, obj, commit = False):

        msg = {'msg' : obj}
        if not commit:
            logger.info('[+] Sending: {0}'.format(msg['msg']))
        else:
            msg['COMMIT'] = obj

        # serialize input
        data = pickle.dumps(obj)

        # padding
        pad = AES.block_size - len(data) % AES.block_size

        # create an header [pck length (4 bytes), pad length (1 byte), random (3 bytes))]
        plaintext = pack('>IB', len(data) + pad + SHA512.digest_size, pad)
        plaintext += Random.new().read(AES.block_size - len(plaintext))
        # add payload plus padding
        plaintext += data
        plaintext += Random.new().read(pad)

        # encryption
        ciphertext = self.cipher_out.encrypt(plaintext)

        # integrity
        hsha = HMAC.new(self.key_hmac_out, digestmod=SHA512.new())
        hsha.update(plaintext)
        hsha.update(pack('>I', self.seq_out))
        self.seq_out = (self.seq_out + 1) & 0xFFFFFFFF
        ciphertext += hsha.digest()

        self.socket.sendall(ciphertext)

    def recv(self, commit = False):

        # read header of next packet
        ciphertext = ""
        brecv = 0
        while brecv < AES.block_size:
            tmp = self.socket.recv(AES.block_size - brecv)
            if not tmp:
                self.close()
                raise Exception("Connection closed (1)")
            brecv += len(tmp)
            ciphertext += tmp

        # decrypt header for length
        header = self.cipher_in.decrypt(ciphertext)
        length, pad = unpack('>IB', header[:5])

        # we don't have yet integrity, be careful with length
        if length > MAX_PACKET_LENGTH:
            self.close()
            raise Exception("MAC Exception (1): length %d" % length)

        ciphertext = ""
        # read the full packet
        brecv = 0
        while brecv < length:
            tmp = self.socket.recv(length - brecv)
            if not tmp:
                self.close()
                raise Exception("Connection closed (2)")
            brecv += len(tmp)
            ciphertext += tmp


        # split mac and ciphertext
        mac = ciphertext[-SHA512.digest_size:]
        ciphertext = ciphertext[:-SHA512.digest_size]
        plaintext = self.cipher_in.decrypt(ciphertext)

        # verify ntegrity
        hsha = HMAC.new(self.key_hmac_in, digestmod=SHA512.new())
        hsha.update(header)
        hsha.update(plaintext)
        hsha.update(pack('>I', self.seq_in))
        self.seq_in = (self.seq_in + 1) & 0xFFFFFFFF

        cmac = hsha.digest()
        if cmac != mac:
            self.close()
            raise Exception("MAC Exception (2) %s != %s" % (cmac.encode('hex'), mac.encode('hex')))

        # passed integrity check, should be a valid pickle data
        data = pickle.loads(plaintext[:-pad])
        if not commit:
            logger.info('[+] Received: {0}'.format(data))

        return data


class MyServerSocket(MySocket):

    def __init__(self, socket, key_server, key_atm):
        self.socket = socket
        self.socket.settimeout(TIMEOUT)

        # receive first packet
        data = self.socket.recv(4096).strip()
        if not data:
            raise Exception("Connection closed (HS BANK)")

        try:
            key = pickle.loads(data)
        except:
            self.close()
            raise Exception("Should be a valid pickle packet: %s" % data.encode('hex'))
        if len(key) != 3 or key[0] != "KEY":
            self.close()
            raise Exception("Expected KEY packet")

        # Decrypt aes key with BANK key
        cipher = PKCS1_OAEP.new(key_server)
        key_aes = cipher.decrypt(key[1])

        # Verify signature with ATM key
        sha = SHA512.new()
        sha.update(key_aes)
        sha.update("CS528PRoject")
        signer = PKCS1_PSS.new(key_atm)
        if not signer.verify(sha, key[2]):
            self.close()
            raise Exception("AtmAuthException")

        # Send (iv + HMAC key)
        iv = Random.new().read(AES.block_size)
        key_hmac = Random.new().read(32)

        # Authenticate iv and hmac key with BANK key
        sha = SHA512.new()
        sha.update(iv + key_hmac)
        sha.update(key_aes)
        sha.update("CS528PRoject")
        signer = PKCS1_PSS.new(key_server)
        signature = signer.sign(sha)

        # Encrypt iv + key_hmac key with ATM key
        cipher = PKCS1_OAEP.new(key_atm)
        ciphertext = cipher.encrypt(iv + key_hmac)

        # Send data
        pck = pickle.dumps(("IV", ciphertext, signature))
        self.socket.sendall(pck)

        # create AES object
        sha = SHA512.new()
        sha.update(iv)
        sha.update('AtB')
        iv_in = sha.digest()[:AES.block_size]

        sha = SHA512.new()
        sha.update(iv)
        sha.update('BtA')
        iv_out = sha.digest()[:AES.block_size]

        sha = SHA512.new()
        sha.update(key_aes)
        sha.update('AtB')
        key_aes_in = sha.digest()[:AES.key_size[0]]

        sha = SHA512.new()
        sha.update(key_aes)
        sha.update('BtA')
        key_aes_out = sha.digest()[:AES.key_size[0]]

        self.cipher_in = AES.new(key_aes_in, AES.MODE_OFB, IV=iv_in)
        self.seq_in = 0
        self.cipher_out = AES.new(key_aes_out, AES.MODE_OFB, IV=iv_out)
        self.seq_out = 0

        # create hmac keys
        sha = SHA512.new()
        sha.update(key_hmac)
        sha.update('AtB')
        self.key_hmac_in = sha.digest()

        sha = SHA512.new()
        sha.update(key_hmac)
        sha.update('BtA')
        self.key_hmac_out = sha.digest()


class MyClientSocket(MySocket):

    def __init__(self, host, port):

        with open('authfile', 'r') as f:
            key = f.read().split("#####")

        key_server = RSA.importKey(key[0])
        key_atm = RSA.importKey(key[1])

        # generate random aes key
        key_aes = Random.new().read(AES.key_size[0])

        # Authenticate aes key with ATM key
        sha = SHA512.new()
        sha.update(key_aes)
        sha.update("CS528PRoject")
        signer = PKCS1_PSS.new(key_atm)
        signature = signer.sign(sha)

        # Encrypt aes key with BANK key
        cipher = PKCS1_OAEP.new(key_server)
        ciphertext = cipher.encrypt(key_aes)

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(1)
        self.socket.connect((host, port))
        pck = pickle.dumps(("KEY", ciphertext, signature))

        self.socket.sendall(pck)

        # Wait for answer
        data = self.socket.recv(4096).strip()
        if not data:
            raise Exception("Connection closed (HS ATM)")
        try:
            data = pickle.loads(data)
        except:
            self.close()
            raise Exception("Should be a valid pickle packet")
        if len(data) != 3 or data[0] != "IV":
            self.socket.close()
            raise Exception("Expected IV packet")

        # Decrypt iv and hmac key with ATM key
        cipher = PKCS1_OAEP.new(key_atm)
        plaintext = cipher.decrypt(data[1])

        iv = plaintext[:AES.block_size]
        key_hmac = plaintext[AES.block_size:]

        # Verify signature with BANK key
        sha = SHA512.new()
        sha.update(plaintext)
        sha.update(key_aes)
        sha.update("CS528PRoject")
        signer = PKCS1_PSS.new(key_server)
        if not signer.verify(sha, data[2]):
            self.close()
            raise Exception("BankAuthException")

        # create AES object
        sha = SHA512.new()
        sha.update(iv)
        sha.update('BtA')
        iv_in = sha.digest()[:AES.block_size]

        sha = SHA512.new()
        sha.update(iv)
        sha.update('AtB')
        iv_out = sha.digest()[:AES.block_size]

        sha = SHA512.new()
        sha.update(key_aes)
        sha.update('BtA')
        key_aes_in = sha.digest()[:AES.key_size[0]]

        sha = SHA512.new()
        sha.update(key_aes)
        sha.update('AtB')
        key_aes_out = sha.digest()[:AES.key_size[0]]

        self.cipher_in = AES.new(key_aes_in, AES.MODE_OFB, IV=iv_in)
        self.seq_in = 0
        self.cipher_out = AES.new(key_aes_out, AES.MODE_OFB, IV=iv_out)
        self.seq_out = 0

        # create hmac keys
        sha = SHA512.new()
        sha.update(key_hmac)
        sha.update('BtA')
        self.key_hmac_in = sha.digest()

        sha = SHA512.new()
        sha.update(key_hmac)
        sha.update('AtB')
        self.key_hmac_out = sha.digest()


class MyServerHandler(SocketServer.BaseRequestHandler):

    def setup(self):
        self.secureRequest = MyServerSocket(self.request, self.server.server_key, self.server.client_key)

    def handle(self):

        if not self.secureRequest:
            return

        try:
            data = self.secureRequest.recv()
            logger.info('[+] {0} wrote: {1}'.format(self.client_address[0], data))

            if DISTRIBUTION == 'G':
                commit_num = geometric(1 - pow(10.0, -3 / float(MAX_COMMIT)))
            elif DISTRIBUTION == 'U':
                commit_num = random_integers(MAX_COMMIT - 1)
            else:
                commit_num = StrongRandom().randint(MIN_COMMIT, MAX_COMMIT)

            self.secureRequest.send(commit_num, True)
            self.secureRequest.commit(commit_num)

            logger.info('Banks says OK')
        except Exception as e:
            # Error in communication
            logger.critical('Bank says Failure')



class ServerSocket(SocketServer.ThreadingMixIn, SocketServer.TCPServer):

    allow_reuse_address = True

    def __init__(self, host, port, num_commits, distribution):
        global MAX_COMMIT
        global DISTRIBUTION

        SocketServer.TCPServer.__init__(self, (host, port), MyServerHandler)

        self.key = self.create_auth_file('authfile')
        MAX_COMMIT = num_commits
        DISTRIBUTION = distribution

    def create_auth_file(self, path):
        try:
            os.remove(path)
        except:
            pass

        # Create two private key
        self.server_key = RSA.generate(KEY_SIZE)
        self.client_key = RSA.generate(KEY_SIZE)

        # save ATM private key and server public key in file
        with open(path,'w+') as f:
            f.write(self.server_key.publickey().exportKey('PEM'))
            f.write("#####")
            f.write(self.client_key.exportKey('PEM'))
