#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# 
# 
# ==================
import time,psutil
import rrdtool
total_input_traffic=psutil.net_io_counters()[1]
total_output_traffic=psutil.net_io_counters()[0]
starttime=int(time.time())
update=rrdtool.updatev('/root/automation/Flow.rrd','%s:%s:%s' % (str(starttime),str(total_input_traffic),str(total_output_traffic)))
print(update)

# if __name__ == "__main__":