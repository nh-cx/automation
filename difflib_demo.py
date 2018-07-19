#!/usr/bin/python3.6
# -*- coding=utf-8 -*-
# 学习专用
import difflib

# 定义字符串1
text1 = """text1:   
This module provides classes and functions for comparing sequences.
including HTML and context and unified diffs.
difflib document v7.4
add string
"""

# 定义字符串2
text2 = """text2:   
This module provides classes and functions for Comparing sequences.
including HTML and context and unified diffs.
difflib document v7.5"""

text1_lines = text1.splitlines()
text2_lines = text2.splitlines()

# 常规输出
# d = difflib.Differ()
# diff = d.compare(text1_lines,text2_lines)
# print('\n'.join(list(diff)))

d = difflib.HtmlDiff()
print(d.make_file(text1_lines, text2_lines))

# if __name__ == "__main__":