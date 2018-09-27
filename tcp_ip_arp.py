#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# 通过scapy发送arp包
# 学习TCP/IP知识
# ==================
from scapy.all import *


def sendARP(local_mac, local_ip, des_ip):
    # 源mac为本地mac，目的mac为广播，操作码为1（请求）
    result_raw = srp(
        Ether(src=local_mac, dst='FF:FF:FF:FF:FF:FF')/ARP(op=1, hwsrc=local_mac, hwdst='00:00:00:00:00:00', psrc=local_ip, pdst=des_ip),verbose=False
    )
    # res: 产生由收发数据包组成的清单(list)
    result_list = result_raw[0].res
    return result_list


if __name__ == "__main__":
    # 配置各种信息，以便调用
    localmac = '00:0c:29:1e:57:a2'
    localip = '192.168.8.229'
    desip = '192.168.8.192'
    ARP_Result = sendARP(localmac, localip, desip)
    print('='*20+'收到的数据包'+'='*20)
    # ARP_Result[0][1],[0]表示第一组数据包（收发），[1]表示收包(0为发包)
    ARP_Result[0][1].show()
    print('='*20+'显示ARP结果'+'='*20)
    print('IP地址：')
    print(ARP_Result[0][1].getlayer(ARP).psrc)
    print('MAC地址：')
    print(ARP_Result[0][1].getlayer(ARP).hwsrc)