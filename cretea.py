#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# 
# 
# ==================
import time
import rrdtool

cur_time = str(int(time.time()))
rrd = rrdtool.create('/root/automation/Flow.rrd', '--step', '10', '--start', cur_time,
                     'DS:eth0_in:COUNTER:600:0:U',
                     'DS:eth0_out:COUNTER:600:0:U',
                     'RRA:AVERAGE:0.5:1:600',
                     'RRA:AVERAGE:0.5:6:700',
                     'RRA:AVERAGE:0.5:24:775',
                     'RRA:AVERAGE:0.5:288:797',
                     'RRA:MAX:0.5:1:600',
                     'RRA:MAX:0.5:6:700',
                     'RRA:MAX:0.5:24:775',
                     'RRA:MAX:0.5:444:797',
                     'RRA:MIN:0.5:1:600',
                     'RRA:MIN:0.5:6:700',
                     'RRA:MIN:0.5:24:775',
                     'RRA:MIN:0.5:444:797')
if rrd:
    print(rrdtool.error())

# if __name__ == "__main__":