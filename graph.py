#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# 
# 
# ==================
import time, psutil
import rrdtool

title = "2 Dog Company network,traffic flow (" + time.strftime('%Y-%m-%d', time.localtime(time.time())) + ")"
rrdtool.graph("/root/automation/Flow.png", "--start", "-1d", "--vertical-label=Bytes/s",
              "--x-grid", "MINUTE:12:HOUR:1:HOUR:1:0:%H", "--width", "650", "--height", "230",
              "--title", title,
              "DEF:inoctets=Flow.rrd:eth0_in:AVERAGE",
              "DEF:outoctets=Flow.rrd:eth0_out:AVERAGE", "CDEF:total=inoctets,outoctets,+",
              "LINE1:total#FF8833:Total traffic", "AREA:inoctets#00FF00:IN traffic",
              "LINE1:outoctets#0000FF:Out traffic", "HRULE:6144#FF0000:Alarm value\\r",
              "CDEF:inbits=inoctets,8,*", "CDEF:outbits=outoctets,8,*",
              "COMMENT:\\r",
              "COMMENT:\\r",
              "GPRINT:inbits:AVERAGE:Avg In traffic\: %6.2lf %Sbps",
              "COMMENT: ", "GPRINT:inbits:MAX:Max In traffic\: %6.2lf %Sbps",
              "COMMENT: ", "GPRINT:inbits:MIN:Min In traffic\: %6.2lf %Sbps\\r", "COMMENT: ",
              "GPRINT:outbits:AVERAGE:Avg OuT traffic\: %6.2lf %Sbps", "COMMENT: ",
              "GPRINT:outbits:MAX:Max OuT traffic\: %6.2lf %Sbps",
              "COMMENT: ", "GPRINT:outbits:MIN:Min OuT traffic\: %6.2lf %Sbps\\r")

# if __name__ == "__main__":