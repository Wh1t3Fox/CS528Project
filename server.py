#!/usr/bin/env python2
from commit import *
import argparse
import logging

logging.basicConfig(filename='output.log', level=logging.DEBUG)
logger = logging.getLogger(__name__)

def parse_args():
      parser = argparse.ArgumentParser(description='Server')
      parser.add_argument('-c', type=int, default=1000, help="number of commits")
      parser.add_argument('-d', type=str, default="G", help="random distribution [G, U]")
      parser.add_argument('-n', type=str, default='127.0.0.1', help="host to listen on")
      parser.add_argument('-p', type=int, default=5000, help="port to listen on")
      args = parser.parse_args()

      # Exponential, Geometric, Uniform
      if args.d not in ['G', 'U']:
          print 'Invalid distribution type'
          exit()

      return args

def main():

    args = parse_args()

    server = ServerSocket(args.n, args.p, args.c, args.d)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        exit()

if __name__ == '__main__':
    main()
