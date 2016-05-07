#!/usr/bin/env python2
from commit import *
import argparse
import logging
import socket
import sys

logging.basicConfig(filename='output.log', level=logging.DEBUG)
logger = logging.getLogger(__name__)

def parse_args():
      parser = argparse.ArgumentParser(description='Client')
      parser.add_argument('-m', type=str, required=True, help="Message to send")
      parser.add_argument('-n', type=str, default='127.0.0.1', help="host to listen on")
      parser.add_argument('-p', type=int, default=4000, help="port to listen on")
      args = parser.parse_args()

      return args


def main():
    args = parse_args()
    sock = MyClientSocket(args.n, args.p)
    try:
        sock.send(args.m)

        # commit protocol
        response = sock.recv()
        sock.commit(int(response))
        sock.close()
    except socket.error:
        # Error in communication
        logger.critical("ATM says Failure")
        return
    logger.info("ATM says OK")


if __name__ == '__main__':
    main()
