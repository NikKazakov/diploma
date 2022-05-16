import slots_classes_p
import dict_p
import dpkt_p
import scapy_p
import custom_p
import creator

import json
from extensions import Rule

if __name__ == "__main__":
    with open('rules.json') as f:
        rules = [Rule(i) for i in json.load(f)]

    path = 'C:/Users/plox/Desktop/1.pcap'
    dict_p.do(path, rules)
'''
    dpath = 'C:/Users/plox/scratch/dumps'
    report = [False] * 5

    descriptors = {'dpkt': dpkt_p.do,
                   'custom': custom_p.do,
                   'slots': slots_classes_p.do,
                   'dict': dict_p.do}

    results2 = {'dpkt': [],
                'custom': [],
                'slots': [],
                'dict': []}

    for i in range(101):
        creator.create_rules(i)
        with open('rules.json') as f:
            rules = [Rule(i) for i in json.load(f)]

        results1 = {'dpkt': [],
                    'custom': [],
                    'slots': [],
                    'dict': []}

        for j in range(1, 13):
            path = f'{dpath}/{j}.pcap'

            for k in descriptors.keys():
                results1[k].append(descriptors[k](path, rules))

        for k in results2.keys():
            results2[k].append(sum(results1[k])/len(results1[k]))

    keys = ('dpkt', 'custom', 'slots', 'dict')
    print('\t'.join(keys))
    try:
        for i in range(101):
            print('\t'.join([str(results2[j][i]) for j in keys]))
    except:
        print(results2)
'''