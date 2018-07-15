#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# 获取本机内存使用情况，返回单位为MB
# mem_total全部内存，mem_used已经使用内存
# ==================
import psutil


def mem_total():
    mem = psutil.virtual_memory()
    # 返回单位为MB
    return int(mem.total/1024/1024)


def mem_used():
    mem = psutil.virtual_memory()
    # 返回单位为MB
    return int(mem.used/1024/1024)

def cpu_count():
    # 返回CPU的逻辑个数
    return  psutil.cpu_count()

def cpu_conut_real():
    # 返回CPU的物理个数
    return psutil.cpu_count(logical=False)


if __name__ == "__main__":
    print('{0:{2}<10}:{1:<6}MB'.format(u'本机总内存为', mem_total(), chr(12288)))
    print('{0:{2}<10}:{1:<6}MB'.format(u'本机已用内存为', mem_used(), chr(12288)))
    print('{0:{2}<10}:{1:<6}MB'.format(u'本机内核逻辑个数', cpu_count(), chr(12288)))