#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# xlsxwriter应用
# 定制自动化物业流量报表周报
# ==================
import xlsxwriter

# 创建一个Excel文件
workbook = xlsxwriter.Workbook('week_report.xlsx')
# 创建一个工作表对象
worksheet = workbook.add_worksheet()

# 创建一个图表对象
chart = workbook.add_chart({'type':'column'})
# 定义数据表头列表
title = [u'业务名称', u'星期一', u'星期二', u'星期三', u'星期四', u'星期五', u'星期六', u'星期日', u'平均流量']
# 定义频道名称
buname = [u'业务官网', u'新闻中心', u'购物频道', u'体育频道', u'亲子频道']
# 5天频道一周七天流量数据列表
data = [
    [150, 152, 158, 149, 155, 145, 148],
    [89, 88, 95, 93, 98, 100, 99],
    [201, 200, 198, 175, 170, 198, 195],
    [75, 77, 78, 78, 74, 70, 79],
    [88, 85, 87, 90, 93, 88, 84]
]
# 定义format格式对象
format = workbook.add_format()
# 定义format对象单元格式边框加粗（1像素）的格式
format.set_border(1)

# 定义format_title格式对象
format_title = workbook.add_format()
# 定义format_title对象单元格边框加粗（1像素）的格式
format_title.set_border(1)
# 定义format_title对象单元格背景颜色为#CCCCCC的格式
format_title.set_bg_color('#CCCCCC')
# 定义format_title对象单元格居中对齐的格式
format_title.set_align('center')
# 定义format_title对象单元格内容加粗的格式
format_title.set_bold()

# 定义format_ave格式对象
format_ave = workbook.add_format()
# 定义format_ave对象单元格边框加粗（1像素）的格式
format_ave.set_border(1)
# 定义format_ave对象单元格数字类别显示格式
format_ave.set_num_format('0.00')

# 下面分别以行或列写入方式将标题、业务名称、流量数据写入起初单元格，同时引用不同格式对象
worksheet.write_row('A1', title, format_title)
worksheet.write_column('A2', buname, format)
worksheet.write_row('B2', data[0], format)
worksheet.write_row('B3',data[1],format)
worksheet.write_row('B4',data[2],format)
worksheet.write_row('B5',data[3],format)
worksheet.write_row('B6',data[4],format)

# 定义图表数据系列函数
def chart_serise(cur_row):
    # 计算（AVERAGE函数）频道周平均流量
    worksheet.write_formula('I'+cur_row, '=AVERAGE(B'+cur_row+':H'+cur_row+')', format_ave)

    chart.add_series(
        {
            #将“星期一至星期日”作为图表数据标签（X轴），频道一周所有数据作为数据区域
            'categories':'=Sheet1!$B$1:$H$1',
            'values'    :'=Sheet1!$B$'+cur_row+':$H$'+cur_row,
            # 线条颜色定义为black（黑色）
            'line'      :{'color':'black'},
            # 引用业务名称为图例项
            'name'      :'=Sheet1!$A$'+cur_row,
        }
    )

for row in range(2, 7):
    chart_serise(str(row))

#设置X轴表格格式，本示例不启用
# chart.set_table()
#设置图表样式，本示例不启用
# chart.set_style(30)

# 设置图表大小
chart.set_size({'width':577, 'height':287})
# 设置图表（上方）大标题
chart.set_title({'name':u'业务流量周报图表'})
# 设置y轴（左侧）小标题
chart.set_y_axis({'name':'Mb/s'})

# 在A8单元格插入图表
worksheet.insert_chart('A8', chart)
print(workbook.filename + "创建成功")
workbook.close()


# if __name__ == "__main__":