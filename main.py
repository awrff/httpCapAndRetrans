from scapy.all import *
from scapy.layers.inet import IP, TCP
import scapy_http.http
import sys
import io
import os
import re
import time
import socket
import struct
import subprocess
from scapy.layers.http import HTTP, HTTPRequest
from scapy.base_classes import Net
from scapy.compat import plain_str, bytes_encode, gzip_compress, gzip_decompress
from scapy.config import conf
from scapy.consts import WINDOWS
from scapy.error import warning, log_loading
from scapy.fields import StrField
from scapy.packet import Packet, bind_layers, bind_bottom_up, Raw
from scapy.supersocket import StreamSocket
from scapy.utils import get_temp_file, ContextManagerSubprocess
from scapy.layers.inet import TCP, TCP_client

def modifyAndRetrans(packet):
    if packet.haslayer('HTTP'):
        if not os.path.exists('./time_sta.txt'):
            st_time = time.time()
            with open('./time_sta.txt', 'w') as f:
                f.write('start time : {}/{:.3f}\nend time : {}'\
                                .format(time.ctime(st_time).split(' ')[3], 
                                st_time, 
                                time.ctime(st_time).split(' ')[3]))
        http_payload = packet.payload.payload.payload.payload
        if http_payload.name == 'HTTP Request':

            host = http_payload.Host
            if http_payload.Path == b'/':
                path = b'/index-content-slider.html'
            else:
                path = http_payload.Path
            iface = None
            iptables = False
            port = packet['TCP'].dport
            timeout = 3
            display = True
            verbose = 0
            raw = False

            from scapy.sessions import TCPSession
            http_headers = {
                "Accept_Encoding": b'gzip, deflate',
                "Cache_Control": b'no-cache',
                "Pragma": b'no-cache',
                "Connection": b'keep-alive',
                "Host": host,
                "Path": path,
            }
            req = HTTP() / HTTPRequest(**http_headers)
            ans = None

            # Open a socket
            if iface is not None:
                raw = True
            if raw:
                # Use TCP_client on a raw socket
                iptables_rule = "iptables -%c INPUT -s %s -p tcp --sport 80 -j DROP"
                if iptables:
                    host = str(Net(host))
                    assert(os.system(iptables_rule % ('A', host)) == 0)
                sock = TCP_client.tcplink(HTTP, host, port, debug=verbose,
                                        iface=iface)
            else:
                # Use a native TCP socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((host, port))
                sock = StreamSocket(sock, HTTP)
            # Send the request and wait for the answer
            try:
                send_time = time.time()
                ans = sock.sr1(
                    req,
                    session=TCPSession(app=True),
                    timeout=timeout,
                    verbose=verbose
                )
                rec_time = time.time()
            finally:
                sock.close()
                if raw and iptables:
                    host = str(Net(host))
                    assert(os.system(iptables_rule % ('D', host)) == 0)
            if ans:
                if display:
                    if Raw not in ans:
                        warning("No HTTP content returned. Cannot display")
                    
                    file_path = '.' + str(path)[2:-1]
                    
                    # Time statistics
                    if not os.path.exists(file_path):
                        file_type = file_path.split('.')[-1]
                        with open('./time_sta.txt', 'r') as f:
                            lines = f.readlines()
                        exist_types = [line.split(' ')[0] for line in lines]
                        if not file_type in exist_types:
                            line = '{} start : {}/{:.3f}, end : {}, takes : {:.3f}s\n'\
                                            .format(file_type, 
                                                    time.ctime(send_time).split(' ')[3], 
                                                    send_time,
                                                    time.ctime(rec_time).split(' ')[3], 
                                                    rec_time - send_time)
                            lines.insert(-1,line)
                        else:
                            for line in lines:
                                if line.startswith(file_type):
                                    f_send_time = float(line.split('/')[1].split(',')[0])
                                    line = line[:line.find('end')] + 'end : {}, takes : {:.3f}s\n'\
                                                    .format(time.ctime(rec_time).split(' ')[3], 
                                                            rec_time - f_send_time)
                        st_time = float(lines[0].split('/')[-1])
                        lines[-1] = 'end time : {}, takes : {:.3f}s'.format(time.ctime(rec_time).split(' ')[3], rec_time - st_time)
                        with open('./time_sta.txt', 'w') as f:
                            f.writelines(lines)
                    
                    # Write file
                    parent_path = file_path[ :file_path.rfind('/')]
                    if parent_path != '.' and not os.path.exists(parent_path):
                        os.makedirs(parent_path)
                    with open(file_path, "wb") as fd:
                        fd.write(ans.load)

sniff(prn=modifyAndRetrans, filter='host 182.61.38.92')