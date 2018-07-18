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

def send_img_mail(username, password, to_address):
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

if __name__ == "__main__":
    username_i = input("Input username:")
    password_i = input("Input password")
    to_address_i = input("Input to address")
    if send_html_mail(username_i, password_i, to_address_i):
        print("邮件发送成功。")
    else:
        print("邮件发送失败。")
