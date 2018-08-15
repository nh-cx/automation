#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# sys_log的SQL部分
# 
# ==================
import pg8000


def insert_url(i_src_ip, i_dst_ip, i_src_mac, i_url, i_v_system='default'):
    conn = pg8000.connect(host='127.0.0.1', user='colin2001', password='~123456', database='mklogdb')
    cursor = conn.cursor()
    cursor.execute("insert into urllist(src_ip, dst_ip, src_mac, url, v_system, v_time) values (i_src_ip, i_dst_ip, i_src_mac, i_url, i_v_system, current_timestamp)")
    conn.commit()

# if __name__ == "__main__":
    # conn = pg8000.connect(host='127.0.0.1', user='colin2001', password='~123456', database='mklogdb')
    # cursor = conn.cursor()
    # cursor.execute("insert into urllist(src_ip, dst_ip, src_mac, url, v_system, v_time) values ('192.168.8.219', '192.168.8.229', '00:50:56:C0:00:0B', 'www.qq.com', 'windows xp', current_timestamp)")
    # cursor.execute("select * from urllist")
    # yourresults = cursor.fetchall()
    # for i in yourresults:
    #     for x in i:
    #         print(x)
    # conn.commit()
