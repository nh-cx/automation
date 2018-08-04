#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# TZFS库
# 根据2.x的版本重新修订的
# 相关网址：https://en.wikipedia.org/wiki/TZSP
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

# 配置连接IP和端口号
UDP_IP = '0.0.0.0'
UDP_PORT = 9999

# 创建socket，IPv4，UDP协议的实例
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# 对实例端口进行绑定
sock.bind((UDP_IP, UDP_PORT))


# 格式化mac地址
def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0], a[1], a[2], a[3], a[4], a[5])
    return b


# 获取Header-Type (1 unsigned byte)，头部的协议类型
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


# 获取Header-Encapsulated protocol (1 unsigned short)，封装的协议类型，占2个字节
def getProtocol(typeData):
    types = {
        0x01: "Ethernet",
        0x12: "IEE 802.11",
        0x77: "Prism Header",
        0x7F: "WLAN AVS"
    }
    return types[typeData]


# 获取Tagged Fields-
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



# if __name__ == "__main__":