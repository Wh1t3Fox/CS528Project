#!/usr/bin/env python2
import os
import sys
import time
import argparse
import subprocess
import logging

logging.basicConfig(filename='output.log', level=logging.DEBUG)
logger = logging.getLogger(__name__)

def parse_args():
      parser = argparse.ArgumentParser(description='Tests')
      parser.add_argument('-c', type=int, default=1000, help="number of commits")
      parser.add_argument('-d', type=str, default="G", help="random distribution [E, G, U]")
      parser.add_argument('-r', type=int, default=10000, help="number of times to run the test")
      args = parser.parse_args()

      # Exponential, Geometric, Uniform
      if args.d not in ['G', 'U']:
          print 'Invalid distribution type'
          exit()

      return (args.c, args.d, args.r)

def main():
    num_commits, dist, num_rounds = parse_args()

    # Launch the BANK
    for c in [10, 100, 1000]:
      for bd in 'GU':
        logger.info('START_DISTRIBUTION: {0} WITH {1} COMMITS'.format(bd, c))
        cmd = 'python2 server.py -c {0} -d {1}'.format(c, bd)
        bp = subprocess.Popen([cmd],
            shell=True,
        )

        # Launch our MiTM for E,G,U
        for d in 'GU':
          cmd = 'python2 mitm.py -c {0} -d {1}'.format(c, d)
          mp = subprocess.Popen([cmd],
              shell=True,
          )

          time.sleep(1)

          # Launch ATMs
          for x in xrange(c*100):
              logger.debug('-------START Client--------')
              cmd = 'python2 client.py -m "Our protocol is neat"'
              ap = subprocess.call([cmd],
                  shell=True,
              )
              logger.debug('-------END Client--------')

          # Kill MITM
          os.system("kill $(ps aux | grep mitm.py | awk '{print $2}') 2> /dev/null")
          logger.info('END_DISTRIBUTION: {0}'.format(bd))

          # Kill the server
          os.system("kill $(ps aux | grep server.py | awk '{print $2}') 2> /dev/null")


if __name__ == '__main__':
    main()
