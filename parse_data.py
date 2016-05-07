#!/usr/bin/env python2
import matplotlib.pyplot as plt
import scipy.stats as stats
import numpy
import sys

filenames = ['commit_10/output_10GG.log', 'commit_10/output_10GU.log',
             'commit_10/output_10UG.log', 'commit_10/output_10UU.log',

             'commit_100/output_100GG.log', 'commit_100/output_100GU.log',
             'commit_100/output_100UG.log', 'commit_100/output_100UU.log',

             'commit_10_10000/output_10GG.log', 'commit_10_10000/output_10GU.log',
             'commit_10_10000/output_10UG.log', 'commit_10_10000/output_10UU.log',
]

def graph_data(lst):
    lst.sort()
    plt.plot(lst, stats.norm.pdf(lst, numpy.mean(lst), numpy.std(lst)))
    plt.hist(lst, normed=True)
    plt.show()

for filename in filenames:
    mitm_lst = []
    commits_lst = []

    with open(filename, 'r') as fr:
        success = fails = 0
        mitm = commit = 0

        for line in fr:
            if 'Nombre' in line:
                mitm = int(line[-2])
                mitm_lst.append(mitm)
            if 'Received' in line:
                try:
                    commit = int(line[-2])
                    commits_lst.append(commit)
                    if mitm == commit:
                        success += 1
                    else:
                        fails += 1

                    mitm = 0
                    commit = 0
                except ValueError:
                    # The Bank Received msg from ATM
                    continue


    total = success + fails
    print "COMMMITS {4}:\tAtm/Bank ({0}) and MiTM ({1}) Resulted in {2}/{3}={5}\tSuccessful Attacks".format(
        filename[-6], filename[-5], success, total, filename[7:filename.find('/')], (success/float(total)*100 ))

    #graph_data(mitm_lst)
