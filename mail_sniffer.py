from scapy.all import sniff,TCP,IP,raw
from scapy.all import Raw

##### what to do with the packet specifically 
def packet_callback(packet):
    
    if type(packet[TCP].payload) == Raw:
        # print(type(packet[TCP].payload))
        mypacket = raw(packet[TCP].payload).decode("utf=8")
        # mypacket = str(packet[TCP].payload)
        if 'user' in mypacket.lower() or "pass" in mypacket.lower():
            print(f"[*] Destination: {packet[IP].dst}")
            print(f"[*]  {mypacket}")

def main():
    sniff(prn=packet_callback,store=2, filter="tcp port 25")

if __name__ == "__main__":
    main()