import argparse
import csv
import datetime
import functools

from scapy.all import Ether, IP, Raw, UDP, wrpcap


HOST_MAC = '00:00:00:00:00:00'
HOST_IP = '10.0.0.0'


@functools.lru_cache(None)
def get_device_mac(port):
    port_num = int(''.join(filter(str.isdigit, port)))
    return (f'{port_num:02}:'*6)[:-1]

@functools.lru_cache(None)
def get_device_ip(port):
    port_num = int(''.join(filter(str.isdigit, port)))
    return f'10.0.0.{port_num}'


parser = argparse.ArgumentParser()
parser.add_argument('--port', default=11243, type=int, help='UDP port')
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
            src_ip, dst_ip = (get_device_ip(row['Port']), HOST_IP)
        else:
            src_mac, dst_mac = (HOST_MAC, get_device_mac(row['Port']))
            src_ip, dst_ip = (HOST_IP, get_device_ip(row['Port']))

        pkt = (
            Ether(src=src_mac, dst=dst_mac) /
            IP(src=src_ip, dst=dst_ip) /
            UDP(sport=args.port, dport=args.port) /
            Raw(load=data)
        )
        pkt.time = \
            datetime.datetime.strptime(row['Time'], '%d/%m/%Y %H:%M:%S')\
            .timestamp()
        packets.append(pkt)



wrpcap(args.output_pcap, packets)
