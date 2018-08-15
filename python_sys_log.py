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
    # import python_sys_log_sql
    # 配置连接IP和端口号
    UDP_IP = '0.0.0.0'
    UDP_PORT = 9999

    # 创建socket，IPv4，UDP协议的实例
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # 对实例端口进行绑定
    sock.bind((UDP_IP, UDP_PORT))
    # encoding = "utf-8"
    conn = pg8000.connect(host='127.0.0.1', user='colin2001', password='~123456', database='mklogdb')
    cursor = conn.cursor()
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
            # 获取源mac地址
            src_mac = python_TZSP.eth_addr(encapsulated_packet_data[6:12])
            eth = dpkt.ethernet.Ethernet(encapsulated_packet_data)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            # print('dpkt src: ', src, ' dpkt dst: ', dst)

            tcp = ip.data

            if tcp.dport == 80 and len(tcp.data) > 0:
                http = dpkt.http.Request(tcp.data)
                if http.uri is not None:
                    if http.uri[-4:] not in ('.jpg', '.png', '.gif', '.css', '.ico') and http.uri[-3:] not in '.js':
                        # print('uri is :::', http.uri)
                        # print('http header is :::', http.headers)
                        URL = http.headers['host'] + http.uri
                        # if 'user-agent' in http.headers.keys():
                        #     print('user-agent is :', http.headers['user-agent'])
                        #     print('http header is :::', http.headers)
                        print('i_src_ip is :', src)
                        print('i_dst_ip is :', dst)
                        print('i_src_mac is :', src_mac)
                        print('URL is :', URL)
                        print('i_v_system is :', http.headers['user-agent'])
                        src_str = "\'"+str(src)+"\'"
                        dst_str = "\'"+str(dst)+"\'"
                        src_mac_str = "\'"+str(src_mac)+"\'"
                        URL_str = "\'"+str(URL)+"\'"
                        http_headers_str = "\'"+str(http.headers['user-agent'])+"\'"
                        str_execute = "insert into urllist(src_ip, dst_ip, src_mac, url, v_system, v_time) values ("+src_str+","+dst_str+","+src_mac_str+","+URL_str+"::varchar(500), "+http_headers_str+"::varchar(150), current_timestamp)"
                        print(str_execute)
                        cursor.execute(str_execute)
                        conn.commit()

        except Exception:
            continue
        except KeyboardInterrupt:
            print('程序终止。')
            sock.close()
            exit()


if __name__ == "__main__":
    main()
