import socket
import os


# host to listen on
HOST ="192.168.116.128"

def main():
	# raw socket
	if os.name == 'nt':
		socket_protocol = socket.IPPROTO_IP
	else:
		socket_protocol = socket.IPPROTO_ICMP

	sniffer = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket_protocol)
	sniffer.bind((HOST,0))
	#### include IP header in capture
	sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)

	if os.name == "nt":
		sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)


	#### read packet
	print(sniffer.recvfrom(65565))

	#### turn off promiscuous mode windows

	if os.name == "nt":
		sniffer.ioctl(socket.SIO_RCVALL,socket.RCVALL_OFF)

if __name__ == "__main__":
	main()
