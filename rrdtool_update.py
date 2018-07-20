#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# rrdtool.updatev更新rrd数据库
# 配合crontab定时执行采样并更新
# ==================
import rrdtool
import time
import psutil

def update_rrd_file():
    # 把本方法的脚本加入到crontab，并配置5分钟作为采集频率，crontab配置如下：
    # */5 * * * * /usr/bin/python3.6 /root/automation/rrdtool_update.py > /dev/null 2>&1
    # 获取网卡入流量
    total_input_traffic = psutil.net_io_counters()[1]
    # 获取网卡出流量
    total_output_traffic = psutil.net_io_counters()[0]
    # 获取当前Linux时间戳
    starttime =  int(time.time())
    # 将获取到的三个数据作为updatev的参数，返回{'return_value':0L}则说明更新成功，反之失败
    update = rrdtool.updatev('Flow.rrd', '{0}:{1}:{2}'.format(str(starttime), str(total_input_traffic), str(total_output_traffic)))
    print(update)

if __name__ == "__main__":
    update_rrd_file()
