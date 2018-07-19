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

    # 将更新文件名或目录追加到holderlist
    for x in only_in_one:
        holderlist.append(os.path.abspath(os.path.join(dir1, x)))

    for x in diff_in_one:
        holderlist.append(os.path.abspath(os.path.join(dir1, x)))

    # 判断是否存在相同子目录，以便递归
    if len(dircomp.common_dirs) > 0:
        for item in dircomp.common_dirs:
            compareme(os.path.abspath(os.path.join(dir1, item)), os.path.abspath(os.path.join(dir2, item)))

    return holderlist


def main():
    # 要求输入源目录和备份目录
    if len(sys.argv) > 2:
        dir1 = sys.argv[1]
        dir2 = sys.argv[2]
    else:
        print("Usage:", sys.argv[0], "datadir backupdir")
        sys.exit()

    # 对比源目录与备份目录
    souce_files = compareme(dir1, dir2)
    dir1 = os.path.abspath(dir1)

    # 备份目录路径增加"/"符
    if not str(dir2).endswith('/'):
        dir2 = dir2 + '/'
    dir2 = os.path.abspath(dir2)
    destination_files = []
    createdir_bool = False

    # 遍历返回的差异文件或目录清单
    for item in souce_files:
        # 将源目录差异路径清单对应替换成备份目录
        destination_dir = re.sub(dir1, dir2, item)

        destination_files.append(destination_dir)

        # 如果差异路径为目录且不存在，则在备份目录中创建
        if os.path.isdir(item):
            if not os.path.exists(destination_dir):
                os.makedirs(destination_dir)
                # 再次调用compareme函数标记
                createdir_bool = True

    # 重新调用compareme函数，并重新遍历新创建目录的内容
    if createdir_bool:
        destination_files = []

        # 调用compareme
        souce_files = compareme(dir1, dir2)
        for item in souce_files:
            destination_dir = re.sub(dir1, dir2, item)
            destination_files.append(destination_dir)

    print("update item:")
    # 输出更新项列表清单
    print(souce_files)
    # 将源目录与备份目录文件清单拆分成元组
    copy_pair = zip(souce_files, destination_files)
    for item in copy_pair:
        if os.path.isfile(item[0]):
            shutil.copyfile(item[0], item[1])


if __name__ == "__main__":
    main()
