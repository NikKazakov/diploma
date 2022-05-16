a = '''Running for C:/Users/plox/scratch/dumps/1.pcap
Scapy: 825.3093834

Dpkt: 40.35350200000005

Custom_classes: 42.44804499999998

Slots_classes: 43.528633799999966

Dict: 23.33802150000008

Running for C:/Users/plox/scratch/dumps/2.pcap
Scapy: 634.8121119999998

Dpkt: 40.40091439999992

Custom_classes: 42.619380699999965

Slots_classes: 43.57832080000003

Dict: 23.219716399999925

Running for C:/Users/plox/scratch/dumps/3.pcap
Scapy: 388.1344756000001

Dpkt: 40.71205069999996

Custom_classes: 43.73002260000021

Slots_classes: 44.45690139999988

Dict: 23.99804710000035

Running for C:/Users/plox/scratch/dumps/4.pcap
Scapy: 376.0785378999999

Dpkt: 41.445518600000014

Custom_classes: 45.477217499999824

Slots_classes: 44.286418799999865

Dict: 23.961237600000004

Running for C:/Users/plox/scratch/dumps/5.pcap
Scapy: 356.9661315999997

Dpkt: 40.57874810000021

Custom_classes: 43.18521270000019

Slots_classes: 44.228450500000235

Dict: 23.474912399999994

Running for C:/Users/plox/scratch/dumps/6.pcap
Scapy: 342.84107410000024

Dpkt: 40.3893165999998

Custom_classes: 43.20328930000005

Slots_classes: 44.614397800000006

Dict: 23.092585299999882

Running for C:/Users/plox/scratch/dumps/7.pcap
Scapy: 350.6224115

Dpkt: 40.85040630000003

Custom_classes: 42.75976119999996

Slots_classes: 43.898652500000026

Dict: 23.246923400000014

Running for C:/Users/plox/scratch/dumps/8.pcap
Scapy: 351.5917823

Dpkt: 40.62904739999976

Custom_classes: 42.809233900000436

Slots_classes: 43.93624

Dict: 23.013886700000512

Running for C:/Users/plox/scratch/dumps/9.pcap
Scapy: 355.32359089999954

Dpkt: 40.481202899999516

Custom_classes: 42.95713210000031

Slots_classes: 44.285131900000124

Dict: 23.37937090000014

Running for C:/Users/plox/scratch/dumps/10.pcap
Scapy: 676.2793689999999

Dpkt: 40.64236379999966

Custom_classes: 42.87906389999989

Slots_classes: 44.290833199999724

Dict: 23.324942100000044

Running for C:/Users/plox/scratch/dumps/11.pcap
Scapy: 1092.4501999999993

Dpkt: 40.77014079999935

Custom_classes: 43.012910500000544

Slots_classes: 43.76752099999976

Dict: 23.512966499999493

Running for C:/Users/plox/scratch/dumps/12.pcap
Scapy: 1121.3817617000004

Dpkt: 42.84827949999999

Custom_classes: 42.88181150000128

Slots_classes: 43.74163729999964

Dict: 23.576798200001576

Running for C:/Users/plox/scratch/dumps/13.pcap
Scapy: 234.73797769999874

Dpkt: 18.15605940000023

Custom_classes: 18.87574289999975

Slots_classes: 19.55802550000044

Dict: 10.039228800000274
'''

r = {'dump': [],
     'Scapy': [],
     'Dpkt': [],
     'Custom_classes': [],
     'Slots_classes': [],
     'Dict': []}
b = ''

for line in a.split('\n'):
    if line:
        if '.pcap' in line:
            b = line[:line.find('.pcap')]
            r['dump'].append(b)
        else:
            name, time = line.split(maxsplit=1)
            name = name[:-1]
            r[name].append(time)

print('\t'.join(r['dump']))
print('\t'.join(r['Scapy']))
print('\t'.join(r['Dpkt']))
print('\t'.join(r['Custom_classes']))
print('\t'.join(r['Slots_classes']))
print('\t'.join(r['Dict']))