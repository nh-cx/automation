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
    # conn = pg8000.connect(host='127.0.0.1', user='colin2001', password='~123456', database='mklogdb')
    # cursor = conn.cursor()

    def Get_Types(self_stream_data):
        """Checks for some special types of packets.

        This method checks for some special packets and assembles usable data
        currently works for: DNS (udp 53), http, netbios (udp 137), ICMP.

        Returns:
          A tuple consisting of a basic desctiption of the stream
          (i.e. HTTP Request) and the prettyfied string for the protocols.
        """
        packet_details = []
        if self_stream_data[:4] == b'HTTP':
            try:
                http = dpkt.http.Response(self_stream_data)
                packet_details.append(u'HTTP Response: status: ')
                packet_details.append(http.status)
                packet_details.append(u' reason: ')
                packet_details.append(http.reason)
                packet_details.append(u' version: ')
                packet_details.append(http.version)
                return u'HTTP Response', packet_details

            except dpkt.UnpackError as exception:
                packet_details = (
                    u'HTTP Response Unpack Error: {0:s}. '
                    u'First 20 of data {1:s}').format(
                    exception, repr(self_stream_data[:20]))
                return u'HTTP Response', packet_details

            except IndexError as exception:
                packet_details = (
                    u'HTTP Response Index Error: {0:s}. First 20 of data {1:s}').format(
                    exception, repr(self_stream_data[:20]))
                return u'HTTP Response', packet_details

            except ValueError as exception:
                packet_details = (
                    u'HTTP Response parsing error: {0:s}. '
                    u'First 20 of data {1:s}').format(
                    exception, repr(self_stream_data[:20]))
                return u'HTTP Response', packet_details

        elif self_stream_data[:3] == b'GET' or self_stream_data[:4] == b'POST':
            try:
                http = dpkt.http.Request(self_stream_data)
                packet_details.append(u'HTTP Request: method: ')
                packet_details.append(http.method)
                packet_details.append(' uri: ')
                packet_details.append(http.uri)
                packet_details.append(' version: ')
                packet_details.append(http.version)
                packet_details.append(' headers: ')
                packet_details.append(repr(http.headers))
                return u'HTTP Request', packet_details

            except dpkt.UnpackError as exception:
                packet_details = (
                    u'HTTP Request unpack error: {0:s}. First 20 of data {1:s}').format(
                    exception, repr(self_stream_data[:20]))
                return u'HTTP Request', packet_details

            except ValueError as exception:
                packet_details = (
                    u'HTTP Request parsing error: {0:s}. '
                    u'First 20 of data {1:s}').format(
                    exception, repr(self_stream_data[:20]))
                return u'HTTP Request', packet_details

        # elif self.protocol == u'UDP' and (
        #         self.source_port == 53 or self.dest_port == 53):
        #     # DNS request/replies.
        #     # Check to see if the lengths are valid.
        #     for packet in self.all_data:
        #         if not packet.ulen == len(packet):
        #             packet_details.append(u'Truncated DNS packets - unable to parse: ')
        #             packet_details.append(repr(self_stream_data[15:40]))
        #             return u'DNS', packet_details
        #
        #     return u'DNS', ParseDNS(self_stream_data)
        #
        # elif self.protocol == u'UDP' and (
        #         self.source_port == 137 or self.dest_port == 137):
        #     return u'NetBIOS', ParseNetBios(dpkt.netbios.NS(self_stream_data))
        #
        # elif self.protocol == u'ICMP':
        #     # ICMP packets all end up as 1 stream, so they need to be
        #     #  processed 1 by 1.
        #     return u'ICMP', ICMPTypes(self.all_data[0])

        elif b'\x03\x01' in self_stream_data[1:3]:
            # Some form of ssl3 data.
            try:
                ssl = dpkt.ssl.SSL2(self_stream_data)
                packet_details.append(u'SSL data. Length: ')
                packet_details.append(str(ssl.len))
                return u'SSL', packet_details
            except dpkt.UnpackError as exception:
                packet_details = (
                    u'SSL unpack error: {0:s}. First 20 of data {1:s}').format(
                    exception, repr(self_stream_data[:20]))
                return u'SSL', packet_details

        elif b'\x03\x00' in self_stream_data[1:3]:
            # Some form of ssl3 data.
            try:
                ssl = dpkt.ssl.SSL2(self_stream_data)
                packet_details.append(u'SSL data. Length: ')
                packet_details.append(str(ssl.len))
                return u'SSL', packet_details

            except dpkt.UnpackError as exception:
                packet_details = (
                    u'SSL unpack error: {0:s}. First 20 of data {1:s}').format(
                    exception, repr(self_stream_data[:20]))
                return u'SSL', packet_details

        return u'other', u'other'
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
            # sor_str = ''.join('\\x%02x' % b for b in encapsulated_packet_data)
            eth = dpkt.ethernet.Ethernet(encapsulated_packet_data)
            # ip = eth.data
            # =================80=================================
            # stream_data = eth.data.data.data
            # if stream_data != '\x00':
            #     print('version::::::', dpkt.http.Request(eth.data.data.data).version)
            #     print('method::::::', dpkt.http.Request(eth.data.data.data).method)
            #     for i in dpkt.http.Request(eth.data.data.data).headers:
            #         print(dpkt.http.Request(eth.data.data.data).headers[i])
            #     print('uri::::::', dpkt.http.Request(eth.data.data.data).uri)
            # else:
            #     print('Other stream :', 'stream_data')
            # =================80=================================

            # ================443=================================
            stream_data = eth.data.data.data
            ssl = dpkt.ssl.SSLFactory(eth.data.data.data)

            print("ssl:::", ssl)
            if b'\x03\x01' == stream_data[1:3]:
                ssl = dpkt.ssl.SSL2(stream_data)
                print(ssl)
            # ================443=================================


            # tcp_stream = encapsulated_packet_data[14:]
            # tcp = dpkt.tcp.TCP(eth.data.data)
            # tcp_str = ''.join(['\\x%02x' % b for b in tcp])
            # print(eth.data.data.data)
            # type_str, details = Get_Types(eth.data.data.data)
            # if type_str != 'other':
            #     print(type_str)
            #     print(type(details[6]))
        except Exception as e:
            print(str(e))
            continue
        except KeyboardInterrupt:
            print('程序终止。')
            sock.close()
            exit()


if __name__ == "__main__":
    main()
