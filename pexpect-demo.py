#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# 
# 
# ==================
import pexpect

child = pexpect.spawn('ssh 192.168.1.228 -l py')
index = child.expect('password', pexpect.EOF, pexpect.TIMEOUT)
print(index)
child.sendline('~123456')
print(child.before)
print(child.after)

# if __name__ == "__main__":