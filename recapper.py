from scapy.all import TCP,rdpcap
import collections
import os
import re 
import sys
import zlib


OUTDIR = "/root/Desktop/pictures"
PCAPS = "/root/Downloads"


Response = collections.namedtuple('Response', ['header', 'payload'])

def get_header(payload):
    try:
        header_raw = payload[:payload.index(b'\r\n\r\n')+2]
    except ValueError:
        sys.stdout.write('-')
        sys.stdout.flush()
        return None
    # import pdb; pdb.set_trace()
    header = dict(re.findall(r'(?P<name>.*?): (?P<value>.*?)\r\n',header_raw.decode()))
    if 'Content-Type' not in header:
        return None
    return header


def extract_content(Response,content_name='image'):
    content, content_type = None, None
    if content_name in Response.header['Content-Type']:
        content_type  = Response.header['Content-Type'].split("/")[1]
        content = Response.payload[Response.payload.index(b'\r\n\r\n')+4:]

        if 'Content-Encoding' in Response.header:
            if Response.header["Content-Encoding"] == 'gzip':
                content = zlib.decompress(Response.payload, zlib.MAX_WBITS | 32 ) 
            elif Response.header["Content-Encoding"] == 'defalte':
                content = zlib.decompress(Response.payload)
    return content, content_type

class Recapper:
    def __init__(self,fname):
        pcap = rdpcap(fname)
        self.sessions = pcap.sessions()
        self.responses = list()
    
    def get_respones(self):

        for session in self.sessions:
            payload = b''
            for packet in self.sessions[session]:
                try:
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        payload += bytes(packet[TCP].payload)
                except IndexError:
                    sys.stdout.write('x')
                    sys.stdout.flush()
            if payload:
                header = get_header(payload)
               
                if header is None:
                    continue
                self.responses.append(Response(header=header,payload=payload))
            

    def write(self,content_name):
        for i, response in enumerate(self.responses):
            content, content_type = extract_content(response,content_name)
            if content and content_type:
                fname = os.path.join(OUTDIR, f'ex_{i}.{content_type}')
                print(f'Writing {fname}')
                with open(fname, 'wb') as f:
                    f.write(content)

if __name__ == '__main__':
    pfile = os.path.join(PCAPS,'pcap.pcap')
    recapper = Recapper(pfile)
    recapper.get_respones()
    recapper.write('image')
