#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# GetTZSP
# 抓取Mikrotik发送过来的TZSP信息(UDP)
# ==================
import socket
address = ('', 9999)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(address)

while 1:
    data, addr = s.recvfrom(2048)
    if not data:
        break
    print('Got data from', addr)
    print(data)

print('closed!')
s.close()

# if __name__ == "__main__":