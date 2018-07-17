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


if __name__ == "__main__":
    username_i = input("Input username:")
    password_i = input("Input password")
    to_address_i = input("Input to address")
    if send_mail(username_i, password_i, to_address_i):
        print("邮件发送成功。")
    else:
        print("邮件发送失败。")
