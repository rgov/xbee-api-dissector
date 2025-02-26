import argparse
import csv
import datetime
import functools

from scapy.all import Ether, Raw, wrpcap


HOST_MAC = '00:00:00:00:00:00'
ETHERTYPE_CUSTOM = 0x4141


@functools.lru_cache(None)
def get_device_mac(port):
    port_num = int(''.join(filter(str.isdigit, port)))
    return (f'{port_num:02}:'*6)[:-1]


parser = argparse.ArgumentParser()
parser.add_argument('input_csv', help='Input CSV file')
parser.add_argument('output_pcap', help='Output PCAP file')
args = parser.parse_args()


packets = []

# Because the "Data (chars)" column contains binary data, we may hit decoding
# errors.
with open(args.input_csv, errors='replace') as csvfile:
    reader = csv.DictReader(csvfile, delimiter=';')
    for row in reader:
        if row['Direction'] != 'UP':
            continue

        data = bytes.fromhex(row['Data'])
        if not data:
            continue

        if row['Function'] == 'IRP_MJ_READ':
            src_mac, dst_mac = (get_device_mac(row['Port']), HOST_MAC)
        else:
            src_mac, dst_mac = (HOST_MAC, get_device_mac(row['Port']))

        pkt = (
            Ether(src=src_mac, dst=dst_mac, type=ETHERTYPE_CUSTOM) /
            Raw(load=data)
        )
        pkt.time = \
            datetime.datetime.strptime(row['Time'], '%d/%m/%Y %H:%M:%S')\
            .timestamp()
        packets.append(pkt)



wrpcap(args.output_pcap, packets)
