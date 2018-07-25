#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# scapy模块
# 用scapy的路由跟踪功能对TCP服务可用性的探测
# ==================
# scapy常用于：
# 对数据包进行伪造或解包（发送数据包、包嗅探、应答和反馈匹配等）
# 处理网络扫描、路由跟踪、服务探测、单元测试等。
import os
import sys
import time
import subprocess
import warnings
import logging
from scapy.all import traceroute

# 屏蔽scapy无用警告信息
warnings.filterwarnings("ignore", category=DeprecationWarning)
# 屏蔽模块IPv6多余警告
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

domains = input('Please input one or more IP/domain:')

target = domains.split()

dport = [80]

if len(target) >=1 and target[0] != '':
    # 启用路由跟踪
    res,unans = traceroute(target, dport=dport, retry = -2)
    # 生成svg矢量图形
    res.graph(target="Done.svg")
    # time.sleep(1)
    # # svg转png格式
    # subprocess.Popen("/usr/bin/convert test.svg test.png", shell=True)
else:
    print("IP/domain number of errors,exit")
# if __name__ == "__main__":