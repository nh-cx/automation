#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# TZFS库
# 根据2.x的版本重新修订的
# 相关网址：https://en.wikipedia.org/wiki/TZSP
# ==================


# 获取Header-Type (1 unsigned byte)，头部的协议类型
def getType(all_data):
    # 数据包的第二位为TZSP的TYPE
    typeData = all_data[1]
    types = {
        0: "Received tag list",
        1: "Packet for transmit",
        2: "Reserved",
        3: "Configuration",
        4: "Keepalive",
        5: "port opener"
    }
    return types[typeData]


# 获取Header-Encapsulated protocol (1 unsigned short)，封装的协议类型，占2个字节
def getProtocol(all_data):
    # TZSP的Protocol占用2个字节，通过运算计算出两个字节的值
    typeData = all_data[2] * 256 + all_data[3]
    types = {
        0x01: "Ethernet",
        0x12: "IEE 802.11",
        0x77: "Prism Header",
        0x7F: "WLAN AVS"
    }
    return types[typeData]


# 获取Tagged Fields-0x00是填料,0x01是结束符号，
# python3传入十进制或者16进制都可以正常匹配，
# 并且传入十六进制不区分大小写
def getTagType(all_data):
    # 数据包的第5位为Tagged的Type
    type = all_data[4]
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


# 获取Tagged Fields字段的Tag data(内容)，如果TagType为"TAG_END"返回None
# 要校验tag_length=0和tag_length = other_data[1]对后续数据的代入公式计算出来封装的包的是否有偏差
def GetTagged_data(all_data):
    tagged_data = None
    # 如果Tagged Type为"TAG_END"，则返回None
    if all_data[4] == 1:
        return tagged_data
    # 如果Tagged Type不为"TAG_END"，返回数据包的第六位
    tag_data_length = all_data[5]
    # 根据tag_data_length，算出tagged_data的内容
    tagged_data = all_data[6:6 + tag_data_length]
    return tagged_data


# 获取Tagged Fieds字段的Tag data的长度，如果TagType为"TAG_END"返回0
def GetTagged_data_length(all_data):
    tag_data_length = 0
    # 如果Tagged Type为"TAG_END"，则返回0
    if all_data[4] == 1:
        return tag_data_length
    # 如果Tagged Type不为"TAG_END"，返回数据包的第六位
    tag_data_length = all_data[5]
    return tag_data_length


# 返回TZSP的封装包
def get_encapsulated_packet(all_data):
    if all_data[4] == 1:
        encapsulated_packet = all_data[5:]
        return encapsulated_packet
    tag_data_length = all_data[5]
    encapsulated_packet = all_data[7 + tag_data_length:]
    return encapsulated_packet


# # 格式化mac地址
# def eth_addr(a):
#     b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0], a[1], a[2], a[3], a[4], a[5])
#     return b


# # 获取以太网（三层)数据类型（如IPv4）
# def getEtherType(etherInt):
#     types = {
#         0x0600: 'XNS Internet Datagram Protocol',
#         0x0800: 'Internet Protocol version 4 (IPv4)',
#         0x0805: 'X.25 Layer 3',
#         0x0806: 'Address Resolution Protocol (ARP)',
#         0x0842: 'Wake-on-LAN',
#         0x08F0: 'WiMax Mac-to-Mac',
#         0x08FF: 'AX.25',
#         0x0BAD: 'Vines IP',
#         0x0BAF: 'Vines Echo',
#         0x0C15: 'ETHERTYPE_C15_HBEAT',
#         0x1984: 'Netmon Train',
#         0x2001: 'Cisco Group Management Protocol',
#         0x22E5: 'Gigamon Header',
#         0x22EA: '802.1Qat Multiple Stream Reservation Protocol',
#         0x22F0: 'IEEE 1722 Audio Video Bridging Transport Protocol',
#         0x22F1: 'Robust Header Compression(RoHC)',
#         0x22F3: 'IETF TRILL Protocol',
#         0x22F4: 'Intermediate System to Intermediate System',
#         0x2452: 'IEEE 802.11 (Centrino promiscuous)',
#         0x3C07: '3Com NBP Datagram',
#         0x3E3F: 'EPL_V1',
#         0x4742: 'ETHERTYPE_C15_CH',
#         0x6000: 'DEC proto',
#         0x6001: 'DEC DNA Dump/Load',
#         0x6002: 'DEC DNA Remote Console',
#         0x6003: 'DEC DNA Routing',
#         0x6004: 'DEC LAT',
#         0x6005: 'DEC Diagnostics',
#         0x6006: 'DEC Customer use',
#         0x6007: 'DEC LAVC/SCA',
#         0x6558: 'Transparent Ethernet bridging',
#         0x6559: 'ETHERTYPE_RAW_FR',
#         0x8035: 'Reverse Address Resolution Protocol',
#         0x8038: 'DEC LanBridge',
#         0x8041: 'DEC LAST',
#         0x809B: 'AppleTalk (Ethertalk)',
#         0x80D5: 'SNA-over-Ethernet',
#         0x80E1: 'EtherNet/IP Device Level Ring',
#         0x80F3: 'AppleTalk Address Resolution Protocol (AARP)',
#         0x8100: 'VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq[8]',
#         0x8133: 'Juniper Netscreen Redundant Protocol',
#         0x8137: 'IPX',
#         0x814C: 'SNMP over Ethernet, RFC 1089',
#         0x80FF: 'Wellfleet Compression Protocol',
#         0x8181: 'Spanning Tree Protocol',
#         0x81FD: 'Cabletron Interswitch Message Protocol',
#         0x81FF: 'Cabletron SFVLAN 1.8 Tag-Based Flood',
#         0x8204: 'QNX Qnet',
#         0x86DD: 'Internet Protocol Version 6 (IPv6)',
#         0x872D: 'Cisco Wireless Lan Context Control Protocol',
#         0x8783: 'Motorola Media Independent Network Transport',
#         0x8808: 'Ethernet flow control',
#         0x8809: 'Slow Protocols',
#         0x880B: 'ETHERTYPE_PPP',
#         0x8819: 'CobraNet',
#         0x8847: 'MPLS unicast',
#         0x8848: 'MPLS multicast',
#         0x885A: 'Foundry proprietary',
#         0x8863: 'PPPoE Discovery Stage',
#         0x8864: 'PPPoE Session Stage',
#         0x886C: 'HomePNA, wlan link local tunnel',
#         0x886D: 'Intel ANS probe',
#         0x886F: 'MS NLB heartbeat',
#         0x8870: 'Jumbo Frames (Obsoleted draft-ietf-isis-ext-eth-01)',
#         0x887B: 'HomePlug 1.0 MME',
#         0x8881: 'CDMA2000 A10 Unstructured byte stream',
#         0x8884: 'ATM over Ethernet',
#         0x888E: 'EAP over LAN (IEEE 802.1X)',
#         0x8892: 'PROFINET Protocol',
#         0x8899: 'Realtek Layer 2 Protocols',
#         0x889A: 'HyperSCSI (SCSI over Ethernet)',
#         0x889B: 'CSM_ENCAPS Protocol',
#         0x88A1: 'Telkonet powerline',
#         0x88A2: 'ATA over Ethernet',
#         0x88A4: 'EtherCAT Protocol',
#         0x88A8: 'Provider Bridging (IEEE 802.1ad) & Shortest Path Bridging IEEE 802.1aq[8]',
#         0x88AB: 'Ethernet Powerlink[citation needed]',
#         0x88AD: 'XiMeta Technology',
#         0x88AE: 'ETHERTYPE_BRDWALK',
#         0x88B4: 'WAI Authentication Protocol',
#         0x88B5: 'Local Experimental Ethertype 1',
#         0x88B6: 'Local Experimental Ethertype 2',
#         0x88B7: 'IEEE 802a OUI Extended Ethertype',
#         0x88B8: 'GOOSE (Generic Object Oriented Substation event)',
#         0x88B9: 'GSE (Generic Substation Events) Management Services',
#         0x88BA: 'SV (Sampled Value Transmission)',
#         0x88CA: 'Transparent Inter Process Communication',
#         0x88C7: '802.11i Pre-Authentication',
#         0x88CC: 'Link Layer Discovery Protocol (LLDP)',
#         0x88CD: 'SERCOS III',
#         0x88D2: 'CDMA2000 A10 3GPP2 Packet',
#         0x88D8: 'Circuit Emulation Services over Ethernet (MEF8)',
#         0x88D9: 'Link Layer Topology Discovery (LLTD)',
#         0x88DC: '(WAVE) Short Message Protocol (WSM)',
#         0x88DE: 'VMware Lab Manager',
#         0x88E1: 'HomePlug AV MME[citation needed]',
#         0x88E3: 'Media Redundancy Protocol (IEC62439-2)',
#         0x88E5: 'MAC security (IEEE 802.1AE)',
#         0x88E7: 'Provider Backbone Bridges (PBB) (IEEE 802.1ah)',
#         0x88EE: 'Ethernet Local Management Interface (MEF16)',
#         0x88F5: 'IEEE 802.1ak Multiple VLAN Registration Protocol',
#         0x88F6: '802.1ak Multiple Mac Registration Protocol',
#         0x88F7: 'Precision Time Protocol (PTP) over Ethernet (IEEE 1588)',
#         0x88F8: 'Network Controller Sideband Interface',
#         0x88FB: 'Parallel Redundancy Protocol (PRP)',
#         0x8901: 'Flow Layer Internal Protocol',
#         0x8902: 'IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)',
#         0x8903: 'Data Center Ethernet (DCE) protocol(Cisco)',
#         0x8906: 'Fibre Channel over Ethernet (FCoE)',
#         0x8909: 'CiscoMetaData',
#         0x890d: 'IEEE 802.11 data encapsulation',
#         0x8911: 'LINX IPC Protocol',
#         0x8914: 'FCoE Initialization Protocol',
#         0x8917: 'Media Independent Handover Protocol',
#         0x891D: 'TTEthernet Protocol Control Frame',
#         0x8926: 'VN-Tag',
#         0x892B: 'Schweitzer Engineering Labs Layer 2 Protocol',
#         0x892F: 'High-availability Seamless Redundancy (HSR)',
#         0x893F: '802.1br Bridge Port Extension E-Tag',
#         0x8940: 'ETHERTYPE_ECP Edge Control Protocol',
#         0x894F: 'Network Service Header',
#         0x9000: 'Ethernet Configuration Testing Protocol[9]',
#         0x9021: 'Real-Time Media Access Control',
#         0x9022: 'Real-Time Configuration Protocol',
#         0x9100: 'VLAN-tagged (IEEE 802.1Q) frame with double tagging',
#         0xCAFE: 'Link Layer Topology Discovery (LLTD)',
#         0xC0DE: 'eXpressive Internet Protocol',
#         0xC0DF: 'Neighborhood Watch Protocol',
#         0xD00D: 'Digium TDM over Ethernet Protocol',
#         0xFCFC: 'ETHERTYPE_FCFT  used to transport FC frames+MDS hdr internal to Cisco MDS switch',
#         0x8915: 'RDMA over Converged Ethernet (RoCE)',
#         0x892D: 'bluecom Protocol'
#     }
#     # 如果能够匹配到以太网类型就返回类型信息，
#     # 如果无法匹配到合适类型，返回未知协议
#     if etherInt in types:
#         return types[etherInt]
#     else:
#         return "UKNOW PROTOCOL:" + str(etherInt)


if __name__ == "__main__":
    import socket
    # from struct import *
    import dpkt
    # 配置连接IP和端口号
    UDP_IP = '0.0.0.0'
    UDP_PORT = 9999

    # 创建socket，IPv4，UDP协议的实例
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # 对实例端口进行绑定
    sock.bind((UDP_IP, UDP_PORT))
    try:
        # encoding = "utf-8"
        while True:
            # 通过socket接收数据
            data, addr = sock.recvfrom(1024)
            # Test
            print('RAW data is :', str(data))
            print('RAW addr is :', addr)

            print('TZSP type is:', getType(data))
            print('TZSP protocol is:', getProtocol(data))
            print('TZSP TagType is:', getTagType(data))

            # dst_mac = eth_addr(data[5:11])
            # src_mac = eth_addr(data[11:17])
            #
            # print('dat_mac is :', dst_mac)
            # print('src_mac is :', src_mac)

            # eth_protocol = data[17] * 256 + data[18]
            # print('3layer Protocol is :', getEtherType(eth_protocol))
            # # iph = unpack('!BBHHHBBH4s4s', data[19:39])
            # # print(iph[0])
            # # print(iph[1])
            # # print(iph[2])
            # # print(iph[3])
            # packet = data[19:]
            # ip_header = packet[0:20]
            # iph = unpack('!BBHHHBBH4s4s', ip_header)

            # version_ihl = iph[0]
            # version = version_ihl >> 4
            # ihl = version_ihl & 0xF
            # iph_length = ihl * 4
            # ttl = iph[5]
            # protocol = iph[6]
            # s_addr = socket.inet_ntoa(iph[8])
            # d_addr = socket.inet_ntoa(iph[9])
            #
            # print('version ', version, ' ttl ', ttl, ' s_addr ', s_addr, ' d_addr ', d_addr)
            # print('other data: ', packet[20:])

            encapsulated_packet = get_encapsulated_packet(data)

            eth = dpkt.ethernet.Ethernet(encapsulated_packet)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)

            print('dpkt src: ', src, ' dpkt dst: ', dst)

            tcp = ip.data

            if tcp.dport == 80 and len(tcp.data) > 0:
                http = dpkt.http.Request(tcp.data)
                print('uri is :::', http.uri)
                # print('http header is :::', http.headers)
                URL = http.headers['host']+http.uri
                print('URL is :', URL)
                print('user-agent is :', http.headers['user-agent'])
        print('closed!')
        s.close()
    finally:
        print("Bye :D")
