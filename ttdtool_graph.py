#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# rrdtool(round robin database)工具为环状数据库的存储格式
# rrdtool模块的常用方法
# ==================
# create    创建rrd数据库
# step      更新频率
# start     起始时间
# DS        数据源
# DST       数据源类型
# RRA       数据周期定义
import rrdtool
import time

# 获取当前Linux时间戳作为rrd起始时间
cur_time = str(int(time.time()))

# 数据写频率 --step为300秒（即5分钟一个数据点）
rrd =rrdtool.create

# 定义数据源eth0_in（入流量）、eht0_out（出流量）；类型都为COUNTER（递增）；600秒为心跳值


# if __name__ == "__main__":