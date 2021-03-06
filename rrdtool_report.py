#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# rrdtool工具为环装数据库的存储格式
# rrdtool的几个日常方法：create、fetch、graph、info、update
# ==================
import rrdtool
import time
import psutil

def create_rrd_file():
    # 获取当前Linux时间戳作为rrd起始时间
    cur_time = str(int(time.time()))


    rrd = rrdtool.create(
        # 数据写频率--step为300秒（即5分钟一个数据点）
        'Flow.rrd', '--step', '300', '--start', cur_time,
        # 定义数据源ens33_in（入流量）、ens33_out（出流量）；类型都是CUNTER（递增）；
        # 600秒为心跳值，就是600秒没收到值，就会用UNKNOWN代替；
        # 0为最小值；最大值用U代替，表示不确定
        'DS:ens33_in:COUNTER:600:0:U',
        'DS:ens33_out:COUNTER:600:0:U',
        # RRA定义格式为[RRA:CF:xff:steps:rows]
        # CF定义了AVERAGE、MAX、MIN三种数据合并方式
        # xxf定义为0.5，表示一个CDP中的PDP值如超过一半值为UNKNOWN，则该CDP的值就被标为UNKNOWN
        # 下列前4个RRA的定义说明如下，其他定义与AVERAGE方式相似，区别是存最大值与最小值
        # 每隔5分钟（1*300秒）     存一次数据的平均值，存600笔，即2.08天
        # 每隔30分钟（6*300秒）    存一次数据的平均值，存700笔，即14.58天（2周）
        # 每隔2小时（24*300秒）    存一次数据的平均值，存775笔，即64.58天（2个月）
        # 每隔24分钟（288*300秒）  存一次数据的平均值，存797笔，即797天（2年）
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
        'RRA:MIN:0.5:444:797'
                         )
    if  rrd:
        print(rrdtool.error())
    print('rrd创建完成。')

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

def graph_rrd_file():
    # 定义图表上方大标题
    title = u"2 Dog Home Network Traffic Flow (" + time.strftime('%Y-%m-%d', time.localtime(time.time())) + ")"

    rrdtool.graph("Flow.png",
                  "--start", "-1d",
                  "--vertical-label=Bytes/s",
                  # 重点解析：
                  # "--x-grid","MINUTE:12:HOUR:1:HOUR:1:0:%H"参数的作用（从左往右进行分解）
                  # "MINUTE:12"   ：表示控制每隔12分钟放置一根次要格线
                  # "HOUR:1"      ：表示控制每隔1小时放置一根主要格线
                  # "HOUR:1"      ：表示控制1小时输出一个label标签
                  # "0:%H"        ：0表示数字对齐格线，%H表示标签以小时显示
                  "--x-grid","MINUTE:12:HOUR:1:HOUR:1:0:%H",
                  "--width", "650",
                  "--height", "230",
                  "--title", title,
                  # 指定网卡入流量数据源DS及CF
                  "DEF:inoctets=Flow.rrd:ens33_in:AVERAGE",
                  # 指定网卡出流量数据源DS及CF
                  "DEF:outoctets=Flow.rrd:ens33_out:AVERAGE",
                  # 通过CDEF合并网卡出入流量，得出总流量total
                  "CDEF:total=inoctets,outoctets,+",

                  # 以线条方式绘制总流量
                  "LINE1:total#FF8833:Total traffic",
                  # 以面积方式绘制入流量
                  "AREA:inoctets#00FF00:In traffic",
                  # 以线条方式绘制出流量
                  "LINE1:outoctets#0000FF:Out traffic",
                  # 绘制水平线，作为警告线，阀值为 6.1k
                  "HRULE:6144#FF0000:Alarm value\\r",
                  # 将入流量换算成bit，即*8，计算结果给inbits
                  "CDEF:inbits=inoctets,8,*",
                  # 将出流量换算成bit，即*8，计算结果给outbits
                  "CDEF:outbits=outoctets,8,*",
                  # 在网格下方输出一个换行符
                  "COMMENT:\\r",
                  "COMMENT:\\r",
                  # 绘制入流量平均值
                  "GPRINT:inbits:AVERAGE:Avg In traffic\: %6.2lf %Sbps",
                  "COMMENT: ",
                  # 绘制入流量最大值
                  "GPRINT:inbits:MAX:Max In traffic\: %6.2lf %Sbps",
                  "COMMENT: ",
                  # 绘制入流量最小值
                  "GPRINT:inbits:MIN:Min In traffic\: %6.2lf %Sbps\\r",
                  "COMMENT: ",
                  # 绘制出流量平均值
                  "GPRINT:outbits:AVERAGE:Avg OuT traffic\: %6.2lf %Sbps",
                  "COMMENT: ",
                  # 绘制出流量最大值
                  "GPRINT:outbits:MAX:Max OuT traffic\: %6.2lf %Sbps",
                  "COMMENT: ",
                  # 绘制出流量最小值
                  "GPRINT:outbits:MIN:MIN Out traffic\: %6.2lf %Sbps\\r"
                  )
    print("图表生成成功。")
if __name__ == "__main__":
    graph_rrd_file()
