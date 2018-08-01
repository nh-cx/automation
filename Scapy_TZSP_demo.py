#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# 
# 
# ==================

from scapy.all import *


def writep(packet):
    udp_packet = packet.payload.payload

    tzsp_packet = udp_packet.payload
    tzsp_packet_str = str(tzsp_packet)

    # remove 4 bytes of header plus first 2 bytes of tagged fields, last byte will give us how many more bytes we need to remove

    tzsp_minus_header_str = tzsp_packet_str[5:]

    try:

        tzsp_decapsulated_packet = Ether(tzsp_minus_header_str)
    except:
        return

    sendp(tzsp_decapsulated_packet, iface="ens33", realtime=True)


def main():
    sniff(iface="ens33", filter="udp", prn=writep).show()


main()