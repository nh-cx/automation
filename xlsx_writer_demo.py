#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# xlsxwriter模块对EXCEL文件操作
# xlsx学习
# ==================
import xlsxwriter

# 创建一个Excel文件
workbook = xlsxwriter.Workbook('demo1.xlsx')


# 创建一个工作表对象
worksheet = workbook.add_worksheet()

# 设置第一列（A)宽度为20像素
worksheet.set_column('A:A', 20)
# 定义一个加粗的格式对象
bold = workbook.add_format({'bold':True})

# A1单元格写入'Hello'
worksheet.write('A1', 'Hello')
# A2单元格写入'World'并引入加粗格式对象bold
worksheet.write('A2', 'World', bold)
# B2单元格写入中文并引用加粗格式对象bold
worksheet.write('B2', u'中文测试', bold)

# 用行列表示法写入数字‘32’与‘35.5’
# 行列表示法的单元格下标以0作为起始值，‘3,0’等价于‘A3’
worksheet.write(2, 0, 32)
worksheet.write(3, 0, 35.3)
# 求A3:A4的和，并将结果写入'4,0',即'A5'
worksheet.write(4, 0, '=SUM(A3:A4)')
worksheet.write(5, 0, '=(A3+A4)')

# 在B5单元格插入图片
worksheet.insert_image('B5', 'img/python-logo.png')


# 创建第二个工作表对象
worksheet2 = workbook.add_worksheet(u'各种数据写入过程')
# 不同数据类型的写入过程
worksheet2.write(0, 0, 'Hello')
worksheet2.write_string(1, 0, 'World')
worksheet2.write_number(2, 0, 2)
worksheet2.write_number(3, 0, 3.00001)
worksheet2.write_formula(4, 0, '=SIN(PI()/4)')
worksheet2.write_blank(5, 0, blank='')
worksheet2.write_blank(6, 0, '')
worksheet2.write_blank(7, 0, None)


# 创建第三个工作表对象
worksheet3 = workbook.add_worksheet(u'各种表格样式操作')
worksheet3.write('A1', 'Hello')
# 定义一个加粗的格式对象
cell_format = workbook.add_format({'bold': True})
# 设置第一行单元格高度为40，而且引用加粗格式对象
worksheet3.set_row(0, 40, cell_format)
worksheet3.set_row(1, None, None, {'hidden': True})

worksheet3.write('A3', 'Hello')
worksheet3.write('B3', 'World')
# 设置3到4列单元格宽度为10像素
worksheet3.set_column(3, 4, 10, cell_format)
# 设置C到D单元格宽度为20像素
worksheet3.set_column('C:D', 20)
# 隐藏E到G列单元格
worksheet3.set_column('E:G', None, None, {'hidden': 1})

# 在A4单元格插入python-logo.png图片，图片超链接为http://python.org
worksheet3.insert_image('A4', 'img/python-logo.png', {'url': 'http://python.org'})


# 创建第四个工作表对象
# area      创建一个面积样式的图表
# bar       创建一个条形样式的图表
# column    创建一个柱形样式的图表
# pie       创建一个饼图样式的图表
# scatter   创建一个散点样式的图表
# stock     创建一个股票样式的图表
# radar     创建一个雷达样式的图表

worksheet4 = workbook.add_worksheet(u'图表操作')
# 创建并初始化数据源
sheet_data = workbook.add_worksheet('sheet_data')
sheet_data.write_number('A1', 1)
sheet_data.write_number('A2', 2)
sheet_data.write_number('A3', 3)
sheet_data.write_number('A4', 4)
sheet_data.write_number('A5', 5)
sheet_data.write_number('B1', 2)
sheet_data.write_number('B2', 4)
sheet_data.write_number('B3', 5)
sheet_data.write_number('B4', 6)
sheet_data.write_number('B5', 10)
sheet_data.write_number('C1', 3)
sheet_data.write_number('C2', 6)
sheet_data.write_number('C3', 9)
sheet_data.write_number('C4', 12)
sheet_data.write_number('C5', 15)
sheet_data.write_number('D1', 2)
sheet_data.write_number('D2', 4)
sheet_data.write_number('D3', 5)
sheet_data.write_number('D4', 6)
sheet_data.write_number('D5', 10)

# 创建一个column(柱形)图表
chart = workbook.add_chart({'type':'column'})
# 图表参数
chart.add_series(
    {
        'categories':'=sheet_data!$D$1:$D$5',
        'values'    :'=sheet_data!$A$1:$A$5',
        'line'      :{'color':'red'},
        'name'      :'One'
    }
)
chart.add_series(
    {
        'categories':'=sheet_data!$D$1:$D$5',
        'values'    :'=sheet_data!$B$1:$B$5',
        'line'      :{'color':'red'},
        'name'      :'Two'
    }
)
chart.add_series(
    {
        'categories':'=sheet_data!$D$1:$D$5',
        'values'    :'=sheet_data!$C$1:$C$5',
        'line'      :{'color':'red'},
        'name'      :'Three'
    }
)
# set_x_axis(options)方法，设置图表X轴选项
chart.set_x_axis(
    {
        # 设置X轴标题名称
        'name':'Earnings per Quarter',
        # 设置X轴标题字体属性
        'name_font': {'size':14, 'bold':True},
        # 设置X轴数字字体属性
        'num_font': {'italic':True},
    }
)

# set_size(options)方法，设置图表大小
chart.set_size(
    {
        'width': 720,
        'height': 576
    }
)

# set_title(options)方法，设置图表标题
chart.set_title(
    {
        'name': 'Year End Results'
    }
)

# set_style(style_id)方法，设置图表样式
chart.set_style(37)

# set_table(options)方法，设置X轴为数据表格式
chart.set_table()

# 在A7单元格插入图表
worksheet4.insert_chart('A7',chart)


print(workbook.filename + "创建成功")
workbook.close()

# if __name__ == "__main__":