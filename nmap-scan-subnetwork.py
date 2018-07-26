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

try:
    nm.scan(hosts=hosts, arguments=' -v -sS -p  '+ port)
except Exception as e:
    print("Scan erro:", str(e))

for host in nm.all_hosts():
    if nm[host].state() == 'up':
        print('-'*30)
        print('Host: {}  ({})'.format(host, nm[host].hostname()))
        print('State: ', nm[host].state())
        for proto in nm[host].all_protocols():
            print('-'*30)
            print('Protocol: ', proto)

            lport = nm[host][proto].keys()
            list(lport).sort()
            for port in lport:
                print('port : {}\tstate: {}'.format(port, nm[host][proto][port]['state']))

# if __name__ == "__main__":
