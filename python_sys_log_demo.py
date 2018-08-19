#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# sys_log主程序
# 
# ==================


def main():
    import socket
    import pg8000
    import dpkt
    from sys import exit
    import python_TZSP
    import pcap_log
    # import python_sys_log_sql
    # 配置连接IP和端口号
    UDP_IP = '0.0.0.0'
    UDP_PORT = 9999

    # 创建socket，IPv4，UDP协议的实例
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # 对实例端口进行绑定
    sock.bind((UDP_IP, UDP_PORT))
    # encoding = "utf-8"
    # conn = pg8000.connect(host='127.0.0.1', user='colin2001', password='~123456', database='mklogdb')
    # cursor = conn.cursor()
    while True:
        try:
            # 通过socket接收数据
            data, addr = sock.recvfrom(1024)
            # Test
            # print('RAW data is :', str(data))
            # print('RAW addr is :', addr)
            #
            # print('TZSP type is:', getType(data))
            # print('TZSP protocol is:', getProtocol(data))
            # print('TZSP TagType is:', getTagType(data))

            # 截取封装数据包
            encapsulated_packet_data = python_TZSP.get_encapsulated_packet(data)
            steam = pcap_log.Stream(encapsulated_packet_data)
            print(steam.source_ip)
        except Exception as e:
            print(str(e))
            continue
        except KeyboardInterrupt:
            print('程序终止。')
            sock.close()
            exit()


if __name__ == "__main__":
    main()
