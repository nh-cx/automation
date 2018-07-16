#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
import difflib
import sys

def readfile(filename):
    try:
        file_handle = open(filename, 'r')
        text = file_handle.read().splitlines()
        file_handle.close()
        return text
    except IOError as error:
        print('Read file Error:'+ str(error))


if __name__ == "__main__":
    try:
        text_file_1 = sys.argv[1]
        text_file_2 = sys.argv[2]
    except Exception as e:
        print('Error:'+ str(e))
        print('Usage:python3 ./difflib_2files_argv.py filename1 filename2')
        sys.exit()

    if text_file_1 =="" or text_file_2 =="":
        print('Usage:python3 ./difflib_2files_argv.py filename1 filename2')
        sys.exit()

    text1_lines = readfile(text_file_1)
    text2_lines = readfile(text_file_2)

    d = difflib.HtmlDiff()

    print(d.make_file(text1_lines, text2_lines))
