#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# nmap网络扫描器
# 通过nmap模块，高效扫描IP、端口、状态等信息
# ==================
import sys
import nmap

scan_row = []
input_data = input("Please input hosts and port:")
scan_row = input_data.split()
if len(scan_row) != 2:
    print("Input error,examp \"192.168.1.0/24 80,443,22\"")
    sys.exit(0)
hosts = scan_row[0]
port = scan_row[1]

try:
    # 创建端口扫描对象
    nm = nmap.PortScanner()
except nmap.PortScannerError:
    print("Nmap not found", sys.exc_info()[0])
    sys.exit(0)
except:
    print("Unexpected error", sys.exc_info()[0])
    exit(0)



# if __name__ == "__main__":
