import socket


target_host = "127.0.0.1"
target_port = 1337


#### socket object
### inet means ipv4
#### sock stream means TCP
client = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

#### no connection just send data, asso sendto instead of send 
client.sendto(b'AABBXX',((target_host,target_port)))

response = client.recvfrom(4096)

print(response.decode())
client.close()