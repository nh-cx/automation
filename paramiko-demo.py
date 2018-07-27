#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# paramiko实现SSH2远程安全连接
# 
# ==================
import paramiko
import getpass


def login_ssh(hostname, username, password, login_port=22, command=''):
    try:
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.connect(hostname=hostname, username=username, password=password, port=login_port)
        stdin, stdout, stderr = ssh.exec_command(command)
        rst_str = str(stdout.read())
        ssh.close()
        return rst_str
    except Exception as e:
        print('Error on ', str(e))


if __name__ == "__main__":
    # 导入pickle，用户创建对象的存放方法
    import pickle
    import datetime
    from os import path
    # 输入用户信息
    host = input('Please input you hostname:')
    user = input('Please input your username:')
    pwd = getpass.getpass('Please input your password:')
    port = 22
    today = str(datetime.date.today())
    # ssh，获取ROS的配置信息，并生成字典，索引为host和today的列表（方便比对IP地址和日期）
    str_backup = {(host+'\t'+today): login_ssh(host, user, pwd, command='export')}

    # 创建文件，通过try来判断文件是否存在，不存在就使用source，存在就使用new来命名
    if path.exists('ssh_source_config.pl'):
        ssh_config_file = open('ssh_config_new.pl', 'wb')
    else:
        ssh_config_file = open('ssh_config_source.pl', 'wb')
    # 把对象写入文件
    pickle.dump(str_backup, ssh_config_file)
    ssh_config_file.close()
    print('备份完毕！')
