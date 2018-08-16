#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# 
# 
# ==================

import pg8000

conn = pg8000.connect(host='127.0.0.1', user='colin2001', password='~123456', database='mklogdb')
cursor = conn.cursor()

try:
    while True:
        search_str = input('Please input the ULR:')
        if search_str is 'q':
            break

        page_num = 0
        page_q = False
        page_step = 10
        while True:
            if page_q:
                break
            print('This page is :', page_num)
            print("select * from urllist where url like \'\%"+search_str+"\%\' limit "+str(page_step)+" offset "+str(page_num)+";")
            cursor.execute("select * from urllist where url like \'%"+search_str+"%\' limit "+str(page_step)+" offset "+str(page_num)+";")
            search_results = cursor.fetchall()
            for i in search_results:
                print('-'*80)
                print('{0:<10}{1}\n{2:<10}{3}\n{4:<10}{5}\n{6:<10}{7}\n{8:<10}{9}\n{10:<10}{11}\n'.format('src_ip:', i[0], 'dst_ip:', i[1], 'src_mac:', i[2], 'URL:', i[3], 'Sys info:', i[4], 'Log time:', i[5]))
                print('-' * 80)
            page_q_str = input('Pre '+str(page_step)+' enter "p",Next '+str(page_step)+' enter "n".\nQuit enter "q"')
            if page_q_str == "p":
                if (page_num-page_step) > 0:
                    page_num = page_num-page_step
                else:
                    page_num = 0
            elif page_q_str == "n":
                page_num = page_num + page_step
            elif page_q_str == "q":
                page_q = True

except Exception as e:
    print(str(e))
