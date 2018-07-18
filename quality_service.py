#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# 通过pycurl模块检测Web服务
# 探测Web服务质量
# ==================
import pycurl
import os
import sys


def show_quality(url):
    c = pycurl.Curl()
    # 定义请求的URL常量
    c.setopt(pycurl.URL, url)
    # 定义请求连接的等待时间
    c.setopt(pycurl.CONNECTTIMEOUT, 5)
    # 定义请求超时时间
    c.setopt(pycurl.TIMEOUT, 5)
    # 屏蔽下载进度条
    c.setopt(pycurl.NOPROGRESS, 1)
    # 完成交互后强制断开连接，不重用
    c.setopt(pycurl.FORBID_REUSE, 1)
    # 指定HTTP重定向的最大数为1
    c.setopt(pycurl.MAXREDIRS, 1)
    # 设置保存DNS信息的时间为30秒
    c.setopt(pycurl.DNS_CACHE_TIMEOUT, 30)
    # 创建一个文件对象，以“wb”方式打开，用来存储返回的http头部及页面内容
    indexfile = open(os.path.dirname(os.path.realpath(__file__))+"/content.txt", "wb")
    # 将返回的HTTP HEADER写入到indexfile文件中
    c.setopt(pycurl.WRITEHEADER, indexfile)
    # 将返回的HTML内容写入到indexfile文件中
    c.setopt(pycurl.WRITEDATA, indexfile)
    try:
        # 提交请求
        c.perform()
    except Exception as e:
        print("Connecion error:"+str(e))
        indexfile.close()
        c.close()
        sys.exit()

    # 获取DNS解析时间
    lookup_time = c.getinfo(c.NAMELOOKUP_TIME)
    # 获取建立连接时间
    connect_time = c.getinfo(c.CONNECT_TIME)
    # 获取从建立连接到准备传输消耗的时间
    pretransfer_time = c.getinfo(c.PRETRANSFER_TIME)
    # 获取从建立连接到传输开始消耗的消耗时间
    starttransfer_time = c.getinfo(c.STARTTRANSFER_TIME)
    # 获取传输的总时间
    total_time = c.getinfo(c.TOTAL_TIME)
    # 获取HTTP状态码
    http_code = c.getinfo(c.HTTP_CODE)
    # 获取下载数据包大小
    size_download = c.getinfo(c.SIZE_DOWNLOAD)
    # 获取HTTP头部大小
    header_size = c.getinfo(c.HEADER_SIZE)
    # 获取平均下载速度
    speed_download = c.getinfo(c.SPEED_DOWNLOAD)

    # 打印输出的相关数据
    print("{0:>10}{1}".format("HTTP状态码：", http_code))
    print("{0:>10}{1:.2f} ms".format("DNS解析时间：", lookup_time*1000))
    print("{0:>10}{1:.2f} ms".format("建立连接时间：", connect_time*1000))
    print("{0:>10}{1:.2f} ms".format("准备传输时间：", pretransfer_time*1000))
    print("{0:>10}{1:.2f} ms".format("传输开始时间：", starttransfer_time*1000))
    print("{0:>10}{1:.2f} ms".format("传输结束总时间：", total_time*1000))
    print("{0:>10}{1} bytes/s".format("下载数据包大小：", size_download))
    print("{0:>10}{1} byte".format("HTTP头部大小：", header_size))
    print("{0:>10}{1} bytes/s".format("平均下载速度：", speed_download))

    # 关闭文件及Curl对象
    indexfile.close()
    c.close()


if __name__ == "__main__":
    MYURL = 'http://www.baidu.com'
    show_quality(MYURL)
