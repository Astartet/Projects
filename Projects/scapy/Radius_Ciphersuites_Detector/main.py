
from cgitb import handler
from lib2to3.pgen2.token import RPAR
from scapy.all import *
from scapy.layers.radius import Radius
import re
import os
import pathlib



def get_ciphersuite():
    ciphersuites = {
        #'0000' : 'TLS_NULL_WITH_NULL_NULL',
        '002f' : 'TLS_RSA_WITH_AES_128_CBC_SHA',
        '0035' : 'TLS_RSA_WITH_AES_256_CBC_SHA',
        '003c' : 'TLS_RSA_WITH_AES_128_CBC_SHA256',
        '003d' : 'TLS_RSA_WITH_AES_256_CBC_SHA256',
        '009c' : 'TLS_RSA_WITH_AES_128_GCM_SHA256',
        '009d' : 'TLS_RSA_WITH_AES_256_GCM_SHA384',
        'c02c' : 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384'
    }
    dir_pcaps = "./pcaps/"
    pcaps = os.listdir(dir_pcaps)
    for pcap in pcaps:
        if pathlib.Path(pcap).suffix in [".pcap", ".cap"]:
            packets = sniff(offline=dir_pcaps+pcap, filter="udp port 1812 and src host 10.10.10.40")
            packet = packets[1]
            print(packet)
            rp = packet.getlayer("Radius")
            print(rp)
            rp_hex = bytes_hex(rp).decode()
            print(rp_hex)
            for ciphersuite in ciphersuites:
                r = re.findall(ciphersuite, rp_hex)
                if r:
                    print(pcap)
                    print(ciphersuites[ciphersuite])
                    print("")
                    break
                else:
                    pass

            
            
            """for packet in packets:
                if packet.haslayer("Radius") and packet[IP].src == "10.10.10.40":
                    rp = packet.getlayer("Radius")
                    rp_hex = bytes_hex(rp).decode()
                    for ciphersuite in ciphersuites:
                        r = re.findall(ciphersuite, rp_hex)
                        if r:
                            print(pcap)
                            print(ciphersuites[ciphersuite])
                            print("")
                            break
                        else:
                            pass"""
                        
get_ciphersuite()
