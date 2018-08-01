#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# paramiko通过私钥加密
# 不会秘钥生成-fail
# ==================
import paramiko
import os

host = '192.168.8.219'
user = 'py'
paramiko.util.log_to_file('syslogin.log')

ssh = paramiko.SSHClient()
ssh.load_system_host_keys()
# 定义私钥存放路径
privatekey = os.path.expanduser('/home/key/id_rsa')
# 创建私钥对象key
key = paramiko.RSAKey.from_private_key_file(privatekey)

ssh.connect(hostname=host, username=user, pkey=key)
stdin, stdout, stderr = ssh.exec_command('/ip add print')
print(stdout.read())
ssh.close()

# if __name__ == "__main__":