#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# TZSP抄一遍
# 
# ==================
import socket
import os
import sys
import json
import time
import signal
import math
import curses
from struct import *
from operator import itemgetter

# 设置开始时间，IP地址，端口
starttime = time.time()
UDP_IP = '0.0.0.0'
UDP_PORT = 9999

# 创建socket，IPv4，UDP协议
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# 对端口进行绑定
sock.bind((UDP_IP, UDP_PORT))


# 按Ctrl+C时候不想看到Traceback那种不友好的信息
def signal_handler(signal, frame):
    sys.exit(0)


# 捕获信号用途
signal_handler(signal.SIGINT, signal_handler)


# 格式化mac地址
def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]), ord(a[1]), ord(a[2]), ord(a[3]), ord(a[4]), ord(a[5]))
    return b


# 获取数据类型
def getType(typeData):
    types = {
        0: "Received tag list",
        1: "Packet for transmit",
        2: "Reserved",
        3: "Configuration",
        4: "Keepalive",
        5: "port opener"
    }
    return types[typeData]


# 获取协议类型
def getProtocol(typeData):
    types = {
        0x01: "Ethernet",
        0x12: "IEE 802.11",
        0x77: "Prism Header",
        0x7F: "WLAN AVS"
    }
    return types[typeData]


# 获取Tag类型（标签）
def getTagType(type):
    types = {
        0x00: "TAG_PADDING",
        0x01: "TAG_END",
        0x0A: "TAG_RAW_RSSI",
        0x0B: "TAG_SNR",
        0x0C: "TAG_DATA_RATE",
        0x0D: "TAG_TIMESTAMP",
        0X0F: "TAG_CONTENTION_FREE",
        0X10: "TAG_DECRYPTED",
        0X11: "TAG_FCS_ERROR",
        0X12: "TAG_RX_CHANNEL",
        0X28: "TAG_PACKET_COUNT",
        0X29: "TAG_RX_FRAME_LENGTH",
        0X3C: "TAG_WLAN_RADIO_HDR_SERIAL"
    }
    return types[type]

# 获取以太网数据类型（如IPv4）
def getEtherType(etherInt):
    types = {
        0x0600: 'XNS Internet Datagram Protocol',
        0x0800: 'Internet Protocol version 4 (IPv4)',
        0x0805: 'X.25 Layer 3',
        0x0806: 'Address Resolution Protocol (ARP)',
        0x0842: 'Wake-on-LAN',
        0x08F0: 'WiMax Mac-to-Mac',
        0x08FF: 'AX.25',
        0x0BAD: 'Vines IP',
        0x0BAF: 'Vines Echo',
        0x0C15: 'ETHERTYPE_C15_HBEAT',
        0x1984: 'Netmon Train',
        0x2001: 'Cisco Group Management Protocol',
        0x22E5: 'Gigamon Header',
        0x22EA: '802.1Qat Multiple Stream Reservation Protocol',
        0x22F0: 'IEEE 1722 Audio Video Bridging Transport Protocol',
        0x22F1: 'Robust Header Compression(RoHC)',
        0x22F3: 'IETF TRILL Protocol',
        0x22F4: 'Intermediate System to Intermediate System',
        0x2452: 'IEEE 802.11 (Centrino promiscuous)',
        0x3C07: '3Com NBP Datagram',
        0x3E3F: 'EPL_V1',
        0x4742: 'ETHERTYPE_C15_CH',
        0x6000: 'DEC proto',
        0x6001: 'DEC DNA Dump/Load',
        0x6002: 'DEC DNA Remote Console',
        0x6003: 'DEC DNA Routing',
        0x6004: 'DEC LAT',
        0x6005: 'DEC Diagnostics',
        0x6006: 'DEC Customer use',
        0x6007: 'DEC LAVC/SCA',
        0x6558: 'Transparent Ethernet bridging',
        0x6559: 'ETHERTYPE_RAW_FR',
        0x8035: 'Reverse Address Resolution Protocol',
        0x8038: 'DEC LanBridge',
        0x8041: 'DEC LAST',
        0x809B: 'AppleTalk (Ethertalk)',
        0x80D5: 'SNA-over-Ethernet',
        0x80E1: 'EtherNet/IP Device Level Ring',
        0x80F3: 'AppleTalk Address Resolution Protocol (AARP)',
        0x8100: 'VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq[8]',
        0x8133: 'Juniper Netscreen Redundant Protocol',
        0x8137: 'IPX',
        0x814C: 'SNMP over Ethernet, RFC 1089',
        0x80FF: 'Wellfleet Compression Protocol',
        0x8181: 'Spanning Tree Protocol',
        0x81FD: 'Cabletron Interswitch Message Protocol',
        0x81FF: 'Cabletron SFVLAN 1.8 Tag-Based Flood',
        0x8204: 'QNX Qnet',
        0x86DD: 'Internet Protocol Version 6 (IPv6)',
        0x872D: 'Cisco Wireless Lan Context Control Protocol',
        0x8783: 'Motorola Media Independent Network Transport',
        0x8808: 'Ethernet flow control',
        0x8809: 'Slow Protocols',
        0x880B: 'ETHERTYPE_PPP',
        0x8819: 'CobraNet',
        0x8847: 'MPLS unicast',
        0x8848: 'MPLS multicast',
        0x885A: 'Foundry proprietary',
        0x8863: 'PPPoE Discovery Stage',
        0x8864: 'PPPoE Session Stage',
        0x886C: 'HomePNA, wlan link local tunnel',
        0x886D: 'Intel ANS probe',
        0x886F: 'MS NLB heartbeat',
        0x8870: 'Jumbo Frames (Obsoleted draft-ietf-isis-ext-eth-01)',
        0x887B: 'HomePlug 1.0 MME',
        0x8881: 'CDMA2000 A10 Unstructured byte stream',
        0x8884: 'ATM over Ethernet',
        0x888E: 'EAP over LAN (IEEE 802.1X)',
        0x8892: 'PROFINET Protocol',
        0x8899: 'Realtek Layer 2 Protocols',
        0x889A: 'HyperSCSI (SCSI over Ethernet)',
        0x889B: 'CSM_ENCAPS Protocol',
        0x88A1: 'Telkonet powerline',
        0x88A2: 'ATA over Ethernet',
        0x88A4: 'EtherCAT Protocol',
        0x88A8: 'Provider Bridging (IEEE 802.1ad) & Shortest Path Bridging IEEE 802.1aq[8]',
        0x88AB: 'Ethernet Powerlink[citation needed]',
        0x88AD: 'XiMeta Technology',
        0x88AE: 'ETHERTYPE_BRDWALK',
        0x88B4: 'WAI Authentication Protocol',
        0x88B5: 'Local Experimental Ethertype 1',
        0x88B6: 'Local Experimental Ethertype 2',
        0x88B7: 'IEEE 802a OUI Extended Ethertype',
        0x88B8: 'GOOSE (Generic Object Oriented Substation event)',
        0x88B9: 'GSE (Generic Substation Events) Management Services',
        0x88BA: 'SV (Sampled Value Transmission)',
        0x88CA: 'Transparent Inter Process Communication',
        0x88C7: '802.11i Pre-Authentication',
        0x88CC: 'Link Layer Discovery Protocol (LLDP)',
        0x88CD: 'SERCOS III',
        0x88D2: 'CDMA2000 A10 3GPP2 Packet',
        0x88D8: 'Circuit Emulation Services over Ethernet (MEF8)',
        0x88D9: 'Link Layer Topology Discovery (LLTD)',
        0x88DC: '(WAVE) Short Message Protocol (WSM)',
        0x88DE: 'VMware Lab Manager',
        0x88E1: 'HomePlug AV MME[citation needed]',
        0x88E3: 'Media Redundancy Protocol (IEC62439-2)',
        0x88E5: 'MAC security (IEEE 802.1AE)',
        0x88E7: 'Provider Backbone Bridges (PBB) (IEEE 802.1ah)',
        0x88EE: 'Ethernet Local Management Interface (MEF16)',
        0x88F5: 'IEEE 802.1ak Multiple VLAN Registration Protocol',
        0x88F6: '802.1ak Multiple Mac Registration Protocol',
        0x88F7: 'Precision Time Protocol (PTP) over Ethernet (IEEE 1588)',
        0x88F8: 'Network Controller Sideband Interface',
        0x88FB: 'Parallel Redundancy Protocol (PRP)',
        0x8901: 'Flow Layer Internal Protocol',
        0x8902: 'IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)',
        0x8903: 'Data Center Ethernet (DCE) protocol(Cisco)',
        0x8906: 'Fibre Channel over Ethernet (FCoE)',
        0x8909: 'CiscoMetaData',
        0x890d: 'IEEE 802.11 data encapsulation',
        0x8911: 'LINX IPC Protocol',
        0x8914: 'FCoE Initialization Protocol',
        0x8917: 'Media Independent Handover Protocol',
        0x891D: 'TTEthernet Protocol Control Frame',
        0x8926: 'VN-Tag',
        0x892B: 'Schweitzer Engineering Labs Layer 2 Protocol',
        0x892F: 'High-availability Seamless Redundancy (HSR)',
        0x893F: '802.1br Bridge Port Extension E-Tag',
        0x8940: 'ETHERTYPE_ECP Edge Control Protocol',
        0x894F: 'Network Service Header',
        0x9000: 'Ethernet Configuration Testing Protocol[9]',
        0x9021: 'Real-Time Media Access Control',
        0x9022: 'Real-Time Configuration Protocol',
        0x9100: 'VLAN-tagged (IEEE 802.1Q) frame with double tagging',
        0xCAFE: 'Link Layer Topology Discovery (LLTD)',
        0xC0DE: 'eXpressive Internet Protocol',
        0xC0DF: 'Neighborhood Watch Protocol',
        0xD00D: 'Digium TDM over Ethernet Protocol',
        0xFCFC: 'ETHERTYPE_FCFT  used to transport FC frames+MDS hdr internal to Cisco MDS switch',
        0x8915: 'RDMA over Converged Ethernet (RoCE)',
        0x892D: 'bluecom Protocol'
    }
    # 如果能够匹配到以太网类型就返回类型信息，
    # 如果无法匹配到合适类型，返回未知协议
    if etherInt in types:
        return types[etherInt]
    else:
        return "UKNOW PROTOCOL:" + str(etherInt)


# 进程标签（计算标签长度？读取标签？）
def processTag(tag, details=False):
    currentTag = None
    i = 0
    # 直到匹配到"TAG_END", "TAG_PADDING"就退出循环
    while currentTag not in [0x00, 0x01]:
        # 把tag[i]转换成ASCII数值
        currentTag = ord(tag[i])
        # 获取tag[0]的ASCI数值，进行Tag的标签匹配
        tagType = getTagType(ord(tag[0]))
        # 初始化标签长度
        tagLength = 0
        # 如果匹配到的标签里面没有TAG_END和TAG_PADDING，
        # tagLength的长度为tag[1]的ASCII数据
        if tagType not in ["TAG_END", "TAG_PADDING"]:
            tagLength = ord(tag[1])
        # 增量运算
        i = i + 1 + tagLength

        # 如果details为假，打印标签格式和长度
        if details:
            print("tag type: %r" % tagType)
            print("tag length: %r" % tagLength)

    return i


# 读取UDP数据？传入数据和mac地址
def processUdpData(data, addr):
    # 截取头部，数据0-3前4个字符
    headers = data[0:4]

    # 剩下的数据，全部放到tags里面
    tags = data

    # 把头部第二个字节转换成ASCII，然后匹配数据类型
    # #GetPrint
    tagType = getType(ord(headers[1]))

    # 拼接协议字符串（ASCII数值）
    protocol = ord(headers[2]) * 256 + ord(headers[3])
    # 获取协议类型
    protocolStr = getProtocol(protocol)
    # 读取Tag标签类型（传输状态？）
    tagsLength = processTag(tags)

    # 截取以太网数据包头部
    eth_header = tags[tagsLength:(14+tagsLength)]
    # 截取以太网数据内容
    eth_data = tags[(14+tagsLength):]
    # 匹配以太网数据包类型
    etherType = getEtherType(ord(eth_header[12])*256 + ord(eth_header[13]))
    # 通过struct模块里面的unpack将字符串解包成为变量,
    # s->char[] / string没有长度 6s就是一个6个字符的字符串 ,
    # H->unsigned short / integer Standard size 2  H就是一个1位的数字，如5，
    # !为大端模式标准对齐方式
    eth = unpack('!6s6sH', eth_header)
    # ntohs()--"Network to Host Short"，主要是为了兼容各种CPU生成的代码
    eth_protocol = socket.ntohs(eth[2])
    # mac地址描述
    mac_details = 'Destination MAC : ' + eth_addr(eth_header[0:6]) + ' Source MAC : ' + eth_addr(eth_header[6:12]) + ' Protocol : ' + str(eth_protocol)

    # 解包IP数据包
    # GetPrint
    # 数据包内容
    packet = tags[15:]
    # 拼接字符串
    hexStr = "".join(tags[21:])
    # ip头部
    # B->unsigned char / integer Standard size 1
    # s->char[] / string没有长度 4s就是一个4个字符的字符串
    iph = unpack('!BBHHHBBH4s4s', packet[:20])
    # ip版本号
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    # ip包长度
    iph_length = ihl * 4
    # ttl值
    ttl = iph[5]
    # 协议类型
    protocol = iph[6]
    # 源地址
    s_addr = socket.inet_ntoa(iph[8])
    # 目标地址
    d_addr = socket.inet_ntoa(iph[9])
    # 连接信息
    connection_detail = ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)

    # 返回字典，源地址，目标地址，以太网类型，长度，连接详细信息，mac详细信息
    return {"s_addr": s_addr, "d_addr": d_addr, "etherType": etherType, "len": len(eth_data), "connection_detail": connection_detail, "mac_details": mac_details}

# if __name__ == "__main__":