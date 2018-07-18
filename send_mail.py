#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# 通过內建模块smtplib发送邮件
# 发送邮件程序
# ==================
import smtplib
from email.mime.text import MIMEText
from email.utils import formataddr
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from email.header import Header


def send_mail(username, password, to_address):
    # 邮件发送状态
    ret = True
    # noinspection PyBroadException
    try:
        msg = MIMEText('填写邮件内容，TEST！', 'plain', 'utf-8')
        # 发件人邮箱账号或者昵称
        msg['From'] = formataddr(['发件人昵称：', username])
        # 收件人邮箱账号或者昵称
        msg['To'] = formataddr(['收件人昵称：', to_address])
        # 邮件主题
        msg['Subject'] = '邮件测试-主题'

        # 发送人邮箱中的SMTP服务器，QQ邮箱是465端口
        server = smtplib.SMTP_SSL('smtp.qq.com', 465)
        # 发件人的账号和密码
        server.login(username, password)
        # 发件人邮箱账号，收件人邮箱账户，发送邮件内容
        server.sendmail(username, [to_address], msg.as_string())
        server.quit()

    except Exception:
        ret = False

    return ret

def send_html_mail(username, password, to_address):
    # 邮件发送状态
    ret = True
    # noinspection PyBroadException
    try:
        html_content = """
        <table width="800" border="0" cellspacing="0" cellpadding="4">
            <tr>
                <td bgcolor="#CECFAD" height="20" style="font-size:14px">*官网数据  <a herf="monitor.domain.com">更多>></a></td>
            </tr>
            <tr>
                <td bgcolor="#EFEBDE" height="100" style="font-size:13px">
                1)日访问量：<font color=red>152433</font>    访问次数：23651  页面浏览量：45123 点击数：545122  数据流量：504M<br>
                2)状态码信息<br>
                &nbsp;&nbsp;500:105 404:3264    503:214<br>
                3)访客浏览器信息<br>
                &nbsp;&nbsp;/index.php 42153<br>
                &nbsp;&nbsp;/view.php 21451<br>
                &nbsp;&nbsp;/login.php 5112<br>
                </td>
            </tr>
        </table>
        """
        msg = MIMEText(html_content, 'html', 'utf-8')
        # 发件人邮箱账号或者昵称
        msg['From'] = formataddr([username, username])
        # 收件人邮箱账号或者昵称
        msg['To'] = formataddr([to_address, to_address])
        # 邮件主题
        msg['Subject'] = '官网流量数据报表'

        # 发送人邮箱中的SMTP服务器，QQ邮箱是465端口
        server = smtplib.SMTP_SSL('smtp.qq.com', 465)
        # 发件人的账号和密码
        server.login(username, password)
        # 发件人邮箱账号，收件人邮箱账户，发送邮件内容
        server.sendmail(username, [to_address], msg.as_string())
        server.quit()

    except Exception:
        ret = False

    return ret


# 添加图片函数
def addimg(src, imgid):
    # 打开文件
    fp = open(src, 'rb')
    # 创建MIMEImage对象，读取图片内容并作为参数
    msgImage = MIMEImage(fp.read())
    # 关闭文件
    fp.close()
    # 指定图片文件的Content-ID,<img>标签src用到
    msgImage.add_header('Content-ID', imgid)

    return msgImage


def send_img_mail(username, password, to_address):
    # 邮件发送状态
    ret = True
    # noinspection PyBroadException
    try:
        # 创建MIMEMultipart对象，采用related定义内嵌资源的邮件体
        msg = MIMEMultipart('related')

        # HTML内容
        text = """
        <table width="600" border="0" cellspacing="0" cellpadding="4">
            <tr bgcolor="#CECFAD" height="100" style="font-size:13px">
                <td colspan=2>* 官网性能数据 <a href="monitor.domain.com>更多</a></td>
            </tr>
            <tr bgcolor="#EFEBDE" height="100" style="font-size:13px">
                <td>
                    <img src="cid:io">
                </td>
                <td>
                    <img src="cid:key_hit">
                </td>
            </tr>
            <tr bgcolor="#EFEBDE" height="100" style="font-size:13px">
                <td>
                    <img src="cid:men">
                </td>
                <td>
                    <img src="cid:swap>
                </td>
            </tr>
        </table>       
        """

        msgtext = MIMEText(text, "html", "utf-8")

        # MIMEMultipart对象附加MIMEText的内容
        msg.attach(msgtext)

        #使用MIMEMultipart对象附加MIMEImage的内容
        msg.attach(addimg("img/bytes_io.png","io"))
        msg.attach(addimg("img/myisam_key_hit.png","key_hit"))
        msg.attach(addimg("img/os_mem.png","men"))
        msg.attach(addimg("img/os_swap.png","swap"))

        # 发件人邮箱账号或者昵称
        msg['From'] = formataddr(['萌萌机器人', username])
        # 收件人邮箱账号或者昵称
        msg['To'] = formataddr(['呆瓜', to_address])
        # 邮件主题
        msg['Subject'] = '业务性能数据报表'

        # 发送人邮箱中的SMTP服务器，QQ邮箱是465端口
        server = smtplib.SMTP_SSL('smtp.qq.com', 465)
        # 发件人的账号和密码
        server.login(username, password)
        # 发件人邮箱账号，收件人邮箱账户，发送邮件内容
        server.sendmail(username, [to_address], msg.as_string())
        server.quit()

    except Exception:
        ret = False

    return ret


def send_img_mail_withfiles(username, password, to_address):
    # 邮件发送状态
    ret = True
    # noinspection PyBroadException
    try:
        # 创建MIMEMultipart对象，采用related定义内嵌资源的邮件体
        msg = MIMEMultipart('related')

        # HTML内容
        text = """
        <font color=red>官网业务周平均延时图表：
            <br>
                <img src=\"cid:myisam_key_hit\" border=\"1\">
            <br>
            详细内容见附件。
        </font>   
        """

        msgtext = MIMEText(text, "html", "utf-8")

        # MIMEMultipart对象附加MIMEText的内容
        msg.attach(msgtext)

        #使用MIMEMultipart对象附加MIMEImage的内容
        msg.attach(addimg("img/myisam_key_hit.png","myisam_key_hit"))

        # # 创建一个MIMEText对象，附加week_report.xlsx文档
        # attach = MIMEText(open("doc/week_report.xlsx", "rb").read(), "base64", "utf-8")
        # # 指定文件格式类型，指定Content-Disposition值为attachment则出现在下载保存对话框，
        # # 保存的默认文件名使用filename指定
        # attach["Content-Type"] = "application/octet-stream"
        # # 由于QQMail使用gb18030页面编码，为保证中文文件名不出现乱码，对文件名进行编码转换
        # attach["Content-Disposition"] = u'attachment; filename=\"周报.xlsx\"','utf-8'
        #
        # # MIMEMultipart对象附加MIMEText附件内容
        # msg.attach(attach)

        rarFilePath = u"解决_ubuntu_安装后字体_发虚_模糊.doc"
        attach = MIMEText(open("doc/week_report.xlsx", "rb").read(), "base64", "utf-8")
        attach["Content-Type"] = "application/octet-stream"
        attach["Content-Disposition"] = "attachment;filename=%s"%Header(rarFilePath,'utf-8').encode()
        print(str(attach["Content-Disposition"]))
        msg.attach(attach)


        # 发件人邮箱账号或者昵称
        msg['From'] = formataddr(['萌萌机器人', username])
        # 收件人邮箱账号或者昵称
        msg['To'] = formataddr(['呆瓜', to_address])
        # 邮件主题
        msg['Subject'] = '业务性能数据报表'

        # 发送人邮箱中的SMTP服务器，QQ邮箱是465端口
        server = smtplib.SMTP_SSL('smtp.qq.com', 465)
        # 发件人的账号和密码
        server.login(username, password)
        # 发件人邮箱账号，收件人邮箱账户，发送邮件内容
        server.sendmail(username, [to_address], msg.as_string())
        server.quit()

    except Exception as e:
        print(str(e))
        ret = False

    return ret


if __name__ == "__main__":
    username_i = input("Input username:")
    password_i = input("Input password")
    to_address_i = input("Input to address")
    if send_img_mail_withfiles(username_i, password_i, to_address_i):
        print("邮件发送成功。")
    else:
        print("邮件发送失败。")
