import ipaddress
from itertools import repeat
import os 
import socket
import struct 
import sys
import threading
import time



SUBNET = '10.0.2.0/24'
MESSAGE = "PYTHONBYTES"




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
class ICMP:
    def __init__(self,buff):
        header = struct.unpack("<BBHHH",buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]



class Scanner:
    def __init__(self,host):
        self.host = host
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP

        self.socket = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket_protocol)
        self.socket.bind((host,0))
        #### include IP header in capture
        self.socket.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)

        if os.name == "nt":
            self.socket.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)
    
    def sniff(self):
        hosts_up = set( [
            f'{str(self.host)} *'
        ])
        try:
            while True:
                raw_buffer = self.socket.recvfrom(65535)[0]
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
                    # print(f"ICMP: Type:{icmp_header.type} Code: {icmp_header.code}")
                    if icmp_header.code == 3 and icmp_header.type ==3:
                        if ipaddress.ip_address(ip_header.src_address) in ipaddress.IPv4Network(SUBNET):
                            if raw_buffer[len(raw_buffer) - len(MESSAGE):] ==bytes(MESSAGE,'utf-8'):
                                tgt = str(ip_header.src_address)
                                if tgt != self.host and tgt not in hosts_up:
                                    hosts_up.add(str(ip_header.src_address))
                                    print(f"Host Up: {tgt}")
        


        except KeyboardInterrupt:
            if os.name == "nt":
                self.socket.ioctl(socket.SIO_RCVALL,socket.RCVALL_OFF)
            print("")
            print("User Interupted.")
            if hosts_up:
                print()
                print()
                print(f"Summary: Host up on {SUBNET}")
                for host in sorted(hosts_up):
                    print(f'{host}')
                print('')
            
            sys.exit()


## spray udp packets
def udp_sender(host):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(SUBNET).hosts():
            if ip == host:
                continue
            sender.sendto(bytes(MESSAGE,'utf-8'), (str(ip),65212))



   

def main():
    if len(sys.argv) ==2:
        host = sys.argv[1]
    else:
        host = "10.0.2.15"
    
    s = Scanner(host)
    time.sleep(5)
    t = threading.Thread(target=udp_sender,args= (host,))
    t.start()
    s.sniff()



if __name__ == "__main__":
	main()
