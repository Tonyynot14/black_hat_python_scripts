import ipaddress
import struct 
import os 
import socket
import sys


class IP:
    def __init__(self,buff=None):
        header= struct.unpack("<BBHHHBBH4s4s",buff)
        self.ver = header[0] >> 4 #### handles 4 bit nibble, basically puts 4 0000s in found of it to be able to get first 4 bits
        self.ihl = header[0] & 0xF #### handles 4 bit nibble, zeros out first 4 

        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        #### human readable ip address
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        #### map protocol number
        self.protocol_map = { 1:"ICMP", 6:"TCP", 17: "UDP"}

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print(f"{e} No protocol for {self.protocol_num}")
            self.protocol = str(self.protocol_num)

def sniff(host):
    
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket_protocol)
    sniffer.bind((host,0))
	#### include IP header in capture
    sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)

    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

    try:
        while True:
            raw_buffer = sniffer.recvfrom(65535)[0]
            ### take first 20 bytes
            ip_header = IP(raw_buffer[0:20])
            

            if ip_header.protocol =='ICMP':
                print(f"Protocol: {ip_header.protocol} {ip_header.src_address} -> {ip_header.dst_address}")
                print(f"Version: {ip_header.ver}")
                print(f"Header Length: {ip_header.ihl} TTL: {ip_header.ttl}")

                ### offset calculate
                offset = ip_header.ihl *4 
                #### TAKE 8 bytes after offset 
                buf = raw_buffer[offset:offset + 8]
                icmp_header = ICMP(buf)
                print(f"ICMP: Type:{icmp_header.type} Code: {icmp_header.code}")


    except KeyboardInterrupt:
        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_OFF)
        sys.exit()


def main():
    if len(sys.argv) ==2:
        host = sys.argv[1]
    else:
        host = "10.0.2.15"
    sniff(host)

class ICMP:
    def __init__(self,buff):
        header = struct.unpack("<BBHHH",buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]



if __name__ == "__main__":
	main()
