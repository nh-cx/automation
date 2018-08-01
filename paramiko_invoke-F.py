#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# paramiko-invoke_shell
# 通过invoke_shell机制实现堡垒机远程
# ==================
import paramiko
import os,sys,time

# 堡垒机信息
blip = '192.168.8.229'
bluser = 'root'
blpasswd = '~123456'

# 业务服务器信息
hostname = '192.168.1.219'
username = 'py'
password = '~123456'
port = 22

# 输入服务器密码的前标志串
passinfo = "\'s password:"
paramiko.util.log_to_file('syslogin.log')

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(hostname=blip, username=bluser, password=blpasswd)

# 创建回话，开启命令调用
channel = ssh.invoke_shell()
channel.settimeout(10)

buff = ''
resp = ''

channel.send('ssh '+hostname+' -l '+username)
# ssh登录的提示信息判断，输出串尾含有"\'s password:"时退出while循环
while not buff.endswith(passinfo):
    try:
        resp = channel.recv(9999)
    except Exception as e:
        print('at')
        print('Error info:', str(e))
        channel.close()
        ssh.close()
        sys.exit()
    buff += str(resp)
    if not buff.find('yes/no')==-1:
        channel.send('yes\n')
        buff = ''

channel.send(password + '\n')

buff = ''

# 输出串尾为'>'时说明校验通过并退出while循环
while not buff.endswith('>'):
    resp = channel.recv(9999)
    # 串尾含有"\'s password:"时说明密码不正确，要求重新输入
    if not resp.find(passinfo) == -1:
        print('Error info:Authentication failed.')
        channel.close()
        ssh.close()
        sys.exit()
    buff += resp

channel.send('/ip add print\n')
print('a')
buff = ''
try:
    while buff.endswith('>') == -1:
        resp = channel.recv(9999)
        buff += resp
except Exception as e:
    print('Error info:', str(e))

print(buff)
channel.close()
ssh.close()

# if __name__ == "__main__":