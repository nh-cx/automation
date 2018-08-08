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

            encapsulated_packet_data = get_encapsulated_packet(data)

            eth = dpkt.ethernet.Ethernet(encapsulated_packet_data)
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
