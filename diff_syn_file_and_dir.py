#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
# ======程序说明======
# 通过filecmp的left_only,diff_files、shutil.copyfile、os.makedirs方法同步文件及文件夹
# 校验源与备份目录差异
# ==================
import os
import sys
import filecmp
import re
import shutil

holderlist = []


# 递归获取更新项函数
def compareme(dir1, dir2):
    dircomp = filecmp.dircmp(dir1, dir2)
    # 源目录新文件或目录
    only_in_one = dircomp.left_only
    # 不匹配文件及发生变化的文件
    diff_in_one = dircomp.diff_files
    # 定义源目录绝对路径
    dirpath = os.path.abspath(dir1)

    # 将更新文件名或目录追加到holderlist
    for x in only_in_one:
        holderlist.append(os.path.abspath(os.path.join(dir1, x)))

    for x in diff_in_one:
        holderlist.append(os.path.abspath(os.path.join(dir1, x)))

    # 判断是否存在相同子目录，以便递归
    if len(dircomp.common_dirs)>0:
        for item in dircomp.common_dirs:
            compareme(os.path.abspath(os.path.join(dir1, item)), os.path.abspath(os.path.join(dir2, item)))

    return holderlist
# if __name__ == "__main__":