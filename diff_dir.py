#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
"""
文件与目录差异对比方法
import filecmp
"""
import filecmp


def show_diff():
    a = "/root/automation/DirDemo/dir1"
    b = "/root/automation/DirDemo/dir2"
    dirobj = filecmp.dircmp(a, b, ['test.py'])

    print('-'*20 + 'report' + '-'*20)
    dirobj.report()
    print()
    print('-' * 20 + 'report_partial_closure' + '-' * 20)
    dirobj.report_partial_closure()
    print()
    print('-' * 20 + 'report_full_closure' + '-' * 20)
    dirobj.report_full_closure()

    print()
    print('-' * 20 + 'other' + '-' * 20)
    print("left_list:" + str(dirobj.left_list))
    print("right_list:" + str(dirobj.right_list))
    print("common:" + str(dirobj.common))
    print("left_only:" + str(dirobj.left_only))
    print("right_only:" + str(dirobj.right_only))
    print("common_dirs:" + str(dirobj.common_dirs))
    print("common_files:" + str(dirobj.common_files))
    print("common_funny:" + str(dirobj.common_funny))
    print("same_files:" + str(dirobj.same_files))
    print("diff_files:" + str(dirobj.diff_files))
    print("funny_files:" + str(dirobj.funny_files))


if __name__ == "__main__":
    # print(filecmp.cmp("/root/automation/DirDemo/dir1/f1", "/root/automation/DirDemo/dir1/f5"))
    # print(filecmp.cmp("/root/automation/DirDemo/dir1/f1", "/root/automation/DirDemo/dir1/f2"))
    # print(filecmp.cmpfiles("/root/automation/DirDemo/dir1", "/root/automation/DirDemo/dir2", ['f1', 'f2', 'f3', 'f4', 'f5']))
    show_diff()
