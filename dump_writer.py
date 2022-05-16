from dpkt import pcap


class DumpWriter:
    def __init__(self):
        self.files_opened = {}

    def write(self, rname, rgroup, file, pkt):
        if file not in self.files_opened:
            self.files_opened[file] = pcap.Writer(open(file, 'wb'), linktype=pkt.ll_type, nano=True)
        self.files_opened[file].writepkt_time(pkt.data, pkt.time)

    def close(self):
        for file in self.files_opened.values():
            file.close()
